# mas fixtures

mas is not installed on the build Mac, so these files are not captured from the owner's Mac.
They follow the documented output of mas v7.0.0 (`mas list --json`, `mas outdated --json`,
`mas version`): one JSON object per app, keys `adamID`, `bundleID`, `name`, `version`,
`newVersion`. Source: https://mpm.run/managers/mas.html and the mas README at tag v7.0.0.
Replace them with captured output when mas is installed.
