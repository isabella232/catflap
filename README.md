The Custom ATlantis FLow APprover allows 2-person approval in Atlantis with GitLab Community Edition.

**The Problem**

Atlantis supports the enforcement of merge approval requirements before Terraform changes can be applied.

Unfortunately GitLab CE does not support requiring merge approvals (https://gitlab.com/gitlab-org/gitlab-foss/-/issues/42096#note_152169378).

**The Solution**

To bridge this gap we can use a property of Atlantis Custom Workflows, which is that they terminate if a step returns a nonzero exit code.

We define two classes of users and groups, admins and approvers.

If a user is defined as an admin or belongs to an LDAP group defined as an admin, they are able to apply both their own and other people's Terraform changes.

If a user is defined as an approver or belongs to an LDAP group defined as an approver, they are able to apply other people's Terraform changes but not their own.

In the Atlantis repo config we define a workflow step that runs catflap with three arguments: the path to the config file, the username and the merge request author's username:

    apply:
      steps:
      - run: catflap -c /etc/catflap.conf -a $USER_NAME -u $PULL_AUTHOR
      - apply

If the user can validly approve the Terraform apply, catflap returns zero and the workflow proceeds; otherwise it returns 1 and the workflow fails.