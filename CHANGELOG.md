# CHANGELOG

<!-- version list -->

## v0.6.0 (2026-11-24)

### Bug Fixes

- **relay**: Review fixes for the guide's IPv6 firewall rule and backup script, and relay serve
  --help
  ([`c9d0040`](https://github.com/ewasserman/squawk/commit/c9d0040fa49f37c6e21bdd419aaeb3b04177b61a))

### Documentation

- First results of the relay access trial, and corrections to the guide
  ([`3cbf317`](https://github.com/ewasserman/squawk/commit/3cbf317bc3d17cf87b0b9abe959ea572107a1b3c))

- Record where the relay trial's corrections went
  ([`4c66042`](https://github.com/ewasserman/squawk/commit/4c66042591ac416deff9443ceedc953ab6581804))

- Relay access trial step 1 passed
  ([`854bcc7`](https://github.com/ewasserman/squawk/commit/854bcc7eec920d29061f369ef7932bc9685b2458))

- Relay access trial step 11 passed; the guide needs a backup method
  ([`6984e8f`](https://github.com/ewasserman/squawk/commit/6984e8f61c975ef1f7b986dbb71594336cec4c3f))

- Relay access trial step 6 passed; home access fixed; correction 12
  ([`7da4d76`](https://github.com/ewasserman/squawk/commit/7da4d76f95f2506e91d32193701c31c52a8dab09))

- Relay access trial steps 4, 5, 7, 8 and 10 passed; two more corrections
  ([`5a57770`](https://github.com/ewasserman/squawk/commit/5a5777049a2cb6f2bcc2d70c8f8813beaac40662))

- Steps for the trial of a relay in github mode over the internet
  ([`475f593`](https://github.com/ewasserman/squawk/commit/475f59339be17355c7374aa9643d88f3bdfa3dc2))

- **relay**: Apply the corrections from the internet trial to the guide
  ([`bbce0d6`](https://github.com/ewasserman/squawk/commit/bbce0d640ee47062f8169287f423c6fdf3481869))

- **relay**: How to install squawk for the relay's user, and run admin commands as that user
  ([`d99d0a3`](https://github.com/ewasserman/squawk/commit/d99d0a3eaf8566f01714285ea6e87bfd8a5178ba))

### Features

- **relay**: Squawk relay serve --help lists its options
  ([`b27ac87`](https://github.com/ewasserman/squawk/commit/b27ac87c9cfcbee9a52db72cc4969131750cdfdc))


## v0.5.0 (2026-11-24)

### Bug Fixes

- End a sign-in when the relay client stops, check the sign-in address is on GitHub, and let removed
  keys reconnect at once
  ([`e01bcf8`](https://github.com/ewasserman/squawk/commit/e01bcf83e66f1be7acec0f65c2d5eb826b05336e))

- **relay**: Say '1 user' rather than '1 users' at startup
  ([`e49694f`](https://github.com/ewasserman/squawk/commit/e49694f0ad03c83b16fbafac873023410e22bc8d))

### Features

- Add squawk relay login, signing this computer in to a relay in github mode
  ([`af91602`](https://github.com/ewasserman/squawk/commit/af91602aa98d0aa1cc66c4eb429cafc7cb3f08e3))

- **relay**: Add squawk relay admin to list users and remove keys
  ([`dfed4db`](https://github.com/ewasserman/squawk/commit/dfed4db42dbf5f6731d6573a36847577bcf9d6bd))


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
