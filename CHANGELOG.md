# CHANGELOG

<!-- version list -->

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
