# Security policy

Bibo runs code written by models, holds credentials for GitHub and for model providers, and decides what reaches a pull request. A security problem in it matters, and we want to hear about it.

## Report a vulnerability privately

Do not open a public issue, discussion or pull request for a vulnerability.

Use GitHub's private vulnerability reporting instead: open the [Security tab of the repository](https://github.com/ortisun/bibo/security) and choose **Report a vulnerability**. Only the maintainers see the report.

Include what you can of the following:

- the part of Bibo that is affected, such as the API, the worker, the sandbox or a gate;
- the steps or the input that show the problem;
- what an attacker could do with it;
- the commit or branch you tested.

## What happens next

A maintainer answers within 7 days to say whether the report is accepted. An accepted report is fixed in a private fork, and the fix is published with a GitHub security advisory that credits the reporter, unless the reporter asks not to be named.

## Supported versions

Bibo has no release yet. Fixes go into the `develop` branch. This section will list supported versions once the first release exists.

## How Bibo is secured

The design and its known limits are public:

- the [threat model](security/threat-model.md);
- the [sandbox policy](security/sandbox-policy.md);
- [secrets and credentials](security/secrets-and-credentials.md);
- the [independent security reviews](reviews/api-security-review.md) and what was fixed after each one.
