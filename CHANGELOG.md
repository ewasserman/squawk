# CHANGELOG

<!-- version list -->

## v0.4.0 (2026-11-23)

### Bug Fixes

- **relay**: Keep renamed GitHub accounts admitted by their pinned id, forget the keys of removed
  users, and recheck access after a sign-in
  ([`296b2d7`](https://github.com/ewasserman/squawk/commit/296b2d7d5942ec6342874c5155c5c3e0a9b8ebe7))

- **relay**: Take keys out only after two readings of the file agree, and never delete mailboxes at
  startup
  ([`99cee73`](https://github.com/ewasserman/squawk/commit/99cee73307ea22dd7606562ab33d1b49ee3eec66))

### Documentation

- Add the plan for relay access control
  ([`114ce15`](https://github.com/ewasserman/squawk/commit/114ce15e9df67a4b537709f5b64b8510999c276d))

- Describe the relay as a supported way to connect in the README
  ([#49](https://github.com/ewasserman/squawk/pull/49),
  [`877b366`](https://github.com/ewasserman/squawk/commit/877b36676c17cb728cd06da5f59fdad912a2159a))

### Features

- Report a relay that refuses this service's key or wants a sign-in, and retry it only every 6 hours
  ([`080e307`](https://github.com/ewasserman/squawk/commit/080e3075a5efe6bbe01eee44ebae3c54270d450e))

- **relay**: Add a client for GitHub's device flow
  ([`1011038`](https://github.com/ewasserman/squawk/commit/1011038799181dada9d31f073855fb6cd8067a2c))

- **relay**: Add an access check after auth, with --access and open mode
  ([`60f414d`](https://github.com/ewasserman/squawk/commit/60f414d6cce912ad7b9feffebf4abab812d78928))

- **relay**: Add github mode, admitting keys whose owner signed in with GitHub
  ([`d963fc5`](https://github.com/ewasserman/squawk/commit/d963fc5252e3fdfe1ee4487d4166d76a1d3063b1))

- **relay**: Add keys mode, admitting only the keys listed in a file
  ([`60e0976`](https://github.com/ewasserman/squawk/commit/60e09767bfcd5a2a72726b5efa0febb9de23a9b6))


## v0.3.1 (2026-11-23)

### Bug Fixes

- Do not tell a session that a relayed message came over the local network, and label the
  local-network part of the offline error
  ([`ce72240`](https://github.com/ewasserman/squawk/commit/ce72240ed28549c1c9411eaf7f023dd001f141ec))

- Keep discovery off when restarting in the guide's relay trial, mention the relay in the session
  note, and drop the repeated offline detail
  ([`127efee`](https://github.com/ewasserman/squawk/commit/127efee624218217fa3fb28dbd06a6ff3636d333))

### Continuous Integration

- Bump the version from conventional commits after the checks pass on main
  ([#48](https://github.com/ewasserman/squawk/pull/48),
  [`67d276b`](https://github.com/ewasserman/squawk/commit/67d276ba83ee4dd14925c973119bb30f612abff5))

### Documentation

- Results of the relay trial with two services on one Mac
  ([`d257229`](https://github.com/ewasserman/squawk/commit/d2572294caca07fa383b93a8ca15c511e936416d))


## v0.3.0 (2026-11-22)

- Initial Release
