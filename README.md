# kotlin-dll-injector

## Build

Build the project using the following command:

```
mvn clean install
```

## Native injection test fixtures

The Windows integration tests use a small native target and DLL. Build them separately from Maven with CMake and Visual Studio 2022:

```powershell
Push-Location '.\native-test-fixtures'
cmake --preset x86
cmake --build --preset x86-release
cmake --preset x64
cmake --build --preset x64-release
Pop-Location
```

For Visual Studio 18 2026, use the matching presets instead:

```powershell
Push-Location '.\native-test-fixtures'
cmake --preset vs2026-x86
cmake --build --preset vs2026-x86-release
cmake --preset vs2026-x64
cmake --build --preset vs2026-x64-release
Pop-Location
```

The Visual Studio 2022 outputs are written below `build/x86` and `build/x64`; the Visual Studio 18 outputs are below `build/vs2026-x86` and `build/vs2026-x64`. For Visual Studio 18, run the Maven tests with these fixture paths:

```powershell
$x86Fixtures = (Resolve-Path '.\native-test-fixtures\build\vs2026-x86\bin').Path
$x64Fixtures = (Resolve-Path '.\native-test-fixtures\build\vs2026-x64\bin').Path
.\mvnw.cmd -B -ntp clean install `
  "-Dinjector.fixture.x86.exe=${x86Fixtures}\injection-target.exe" `
  "-Dinjector.fixture.x86.dll=${x86Fixtures}\injector-fixture.dll" `
  "-Dinjector.fixture.x64.exe=${x64Fixtures}\injection-target.exe" `
  "-Dinjector.fixture.x64.dll=${x64Fixtures}\injector-fixture.dll"
```

For Visual Studio 2022, use the corresponding `build/x86/bin` and `build/x64/bin` directories instead.

Without fixture properties, the unit tests still run and the Windows process-injection tests are skipped. The fixture DLL writes a marker file from `DllMain`; the tests do not display UI or depend on an interactive desktop.

## References

- https://www.ired.team/offensive-security/code-injection-process-injection/finding-kernel32-base-and-function-addresses-in-shellcode
