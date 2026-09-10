const version = process.env.RELEASE_VERSION ?? "";
if (
  !/^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-((?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*))?$/.test(
    version,
  ) ||
  version.length > 128
) {
  throw new Error("Expected a SemVer tag such as v1.0.0 or v1.0.0-rc.1");
}
