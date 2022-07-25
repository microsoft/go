# Guardian

Guardian is an internal Microsoft tool written in .NET that runs a suite of SDL (Security Development Lifecycle) tools. It also runs PoliCheck, which is not an SDL tool, but it is convenient to let Guardian run it and report the results.

Internal rolling builds run Guardian and report results.

The microsoft/go implementation of Guardian execution is based on [dotnet/arcade](https://github.com/dotnet/arcade). See [HowToAddSDLRunToPipeline.md](https://github.com/dotnet/arcade/blob/main/Documentation/HowToAddSDLRunToPipeline.md).

# Running Guardian locally on Windows

Microsoft internal auth is necessary to download the SDL tools.

1. Create a temporary folder, e.g. `C:\temp\sdl`.
1. Go to
    https://dev.azure.com/SecurityTools/SecurityIntegration/_packaging?_a=package&feed=Guardian&package=Microsoft.Guardian.Cli&protocolType=NuGet
    and download the desired version.
1. Extract the `nupkg` file (it's just a `zip`) to a known location like `C:\temp\guardian`.
1. Clone the Go repo into `C:\temp\sdl\src`.
1. Place artifacts to validate into `C:\temp\sdl\artifacts`.
    1. To validate a `zip` or `tar.gz`, extract it.
1. Open a powershell terminal.
    1. The build job uses `powershell`, not `pwsh`.
1. Set `$env:BUILD_ARTIFACTSTAGINGDIRECTORY = "C:\temp\sdl"`
1. Set `$env:BUILD_SOURCESDIRECTORY = "C:\temp\sdl\go"`
1. In `C:\temp\sdl`, run:
    ```powershell
    & go\eng\compliance\Guardian\execute-go-sdl-tools.ps1 `
        -GuardianCliLocation C:\temp\sdl\guardian\tools\guardian.cmd `
        -WorkingDirectory C:\temp\sdl
    ```

Some steps (such as PoliCheck) may refuse to run locally due to lack of authentication, even if you have Microsoft internal auth. Those must be run in the internal rolling (official) build job. Running Guardian locally only confirms some basic functionality.
