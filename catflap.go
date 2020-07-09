package main

import (
  "crypto/x509"
  "crypto/tls"
  "flag"
  "io/ioutil"
  "fmt"
  "log"
  "os"
  "gopkg.in/ldap.v2"
  "gopkg.in/yaml.v2"
)

type config struct {
  Adminldapgroups []string
  Adminusernames []string
  Approverldapgroups []string
  Approverusernames []string
  Ldapbasedn string
  Ldapbinddn string
  Ldapbindpassword string
  Ldapport int
  Ldapserver string
}

// Our configuration file applies globally, so declare it globally.
var myconfig config

// isUserInList returns True if a specified username appears in a list of
// allowed users, otherwise it returns False.
func isUserInList(user string, allowedUsers []string) bool {
  for _, allowedUser := range allowedUsers {
    if user == allowedUser {
      return true
    }
  }
  return false
}

// isUserInGroups connects to the LDAP server specified in our configuration
// and checks whether any of the user's groups are in a list of allowed
// groups. If so it returns True, otherwise it returns False.
func isUserInGroups(user string, allowedLDAPGroups []string) bool {
  // If we don't have an LDAP server then just return False.
  if myconfig.Ldapserver == "" {
    log.Printf("No LDAP server defined, skipping LDAP group check.")
    return false
  }
  // Initialise TLS. (We do not support unencrypted LDAP connections; everyone
  // should use LDAPS.)
  rootCA, err := x509.SystemCertPool()
  if err != nil {
    log.Printf("Failed to load system CA certs: %v", err)
    panic(err)
  }
  if rootCA == nil {
    rootCA = x509.NewCertPool()
  }
  tlsConfig := tls.Config{
    ServerName: myconfig.Ldapserver,
    RootCAs:    rootCA,
    MinVersion: tls.VersionTLS12,
  }
  // Connect to the LDAP server.
  ldapConn, err := ldap.DialTLS("tcp", fmt.Sprintf("%s:%d", myconfig.Ldapserver, myconfig.Ldapport), &tlsConfig)
  // In the event of a connect failure, log the error but return False so that
  // we handle the failure gracefully.
  if err != nil {
    log.Printf("Failed to connect to LDAP server: %v", err)
    return false
  }
  // Bind to the LDAP server with the credentials from our config file.
  err = ldapConn.Bind(myconfig.Ldapbinddn, myconfig.Ldapbindpassword)
  // In the event of a bind failure, log the error but return False so that we
  // handle the failure gracefully.
  if err != nil {
    log.Printf("Failed to bind to LDAP server: %v", err)
    return false
  }
  // Search for the specified user's LDAP groups.
  res, err := ldapConn.Search(ldap.NewSearchRequest(myconfig.Ldapbasedn, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false, fmt.Sprintf("(memberUid=%s)", user), []string{"dn"}, nil))
  // In the event of a search query failure, log the error but return False so
  // that we handle the failure gracefully.
  if err != nil {
    log.Printf("Failed to query LDAP server: %v", err)
    return false
  }
  // Now that we have the list of the user's LDAP groups, loop through them
  // and check whether any of them matches any of the allowed LDAP groups. If
  // so return True.
  for i := 0; i < len(res.Entries); i++ {
    for _, allowedLDAPGroup := range allowedLDAPGroups {
      if res.Entries[i].DN == allowedLDAPGroup {
        return true
      }
    }
  }
  return false
}

func main() {
  // Read our command-line arguments. We take three arguments; the path to our
  // config file, the change request author and the user trying to apply the
  // change. The latter two should be passed in from Atlantis, using the
  // $PULL_AUTHOR and $USER_NAME environment variables:
  // https://www.runatlantis.io/docs/custom-workflows.html#reference
  var author string
  var configpath string
  var user string
  flag.StringVar(&author, "a", "", "The user who authored the change request.")
  flag.StringVar(&configpath, "c", "", "The path to the config file.")
  flag.StringVar(&user, "u", "", "The user running the current command.")
  flag.Parse()
  if author == "" || configpath == "" || user == "" {
    fmt.Println("Usage: approvalcheck -c /path/to/config.yaml -a author -u user")
    os.Exit(1)
  }

  // Read and parse our configuration file. If there's an error, panic; we
  // can't do anything without valid configuration.
  configfile, err := ioutil.ReadFile(configpath)
  if err != nil {
    panic(err)
  }
  err = yaml.Unmarshal(configfile, &myconfig)
  if err != nil {
    panic(err)
  }
  // The default LDAP port is 636.
  if myconfig.Ldapport == 0 {
    myconfig.Ldapport = 636
  }

  // We now check approvals and return either 0 (allowing the Atlantis custom
  // workflows to proceed) or 1 (halting the Atlantis custom workflow with an
  // error).
  // This is the current recommended approach as per:
  // https://github.com/runatlantis/atlantis/issues/438
  // https://github.com/runatlantis/atlantis/issues/764

  // Admin users can approve anything.
  if isUserInList(user, myconfig.Adminusernames) || isUserInGroups(user, myconfig.Adminldapgroups) {
    fmt.Printf("%s is a valid approver for %s.\n", user, author)
    os.Exit(0)
  // Normal approvers can approve for others, but not themselves.
  } else if isUserInList(user, myconfig.Approverusernames) || isUserInGroups(user, myconfig.Approverldapgroups) {
    if user != author {
      fmt.Printf("%s is a valid approver for %s.\n", user, author)
      os.Exit(0)
    } else {
      fmt.Printf("%s is a valid approver, but cannot self-approve.\n", user)
      os.Exit(1)
    }
  // If they weren't a valid admin user or approver, they don't have permissions.
  } else {
      fmt.Printf("%s is not a valid approver.\n", user)
      os.Exit(1)
  }
}

