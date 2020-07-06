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

var myconfig config

func isUserInList(user string, allowedUsers []string) bool {
  for _, allowedUser := range allowedUsers {
    if user == allowedUser {
      return true
    }
  }
  return false
}

func isUserInGroups(user string, allowedLDAPGroups []string) bool {
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
  ldapConn, err := ldap.DialTLS("tcp", fmt.Sprintf("%s:%d", myconfig.Ldapserver, myconfig.Ldapport), &tlsConfig)
  err = ldapConn.Bind(myconfig.Ldapbinddn, myconfig.Ldapbindpassword)
  if err != nil {
    panic(err)
  }
  res, err := ldapConn.Search(ldap.NewSearchRequest(myconfig.Ldapbasedn, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false, fmt.Sprintf("(memberUid=%s)", user), []string{"dn"}, nil))
  if err != nil {
    panic(err)
  }
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

  configfile, err := ioutil.ReadFile(configpath)
  if err != nil {
    panic(err)
  }
  err = yaml.Unmarshal(configfile, &myconfig)
  if err != nil {
    panic(err)
  }

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
  } else {
      fmt.Printf("%s is not a valid approver.\n", user)
      os.Exit(1)
  }
}

