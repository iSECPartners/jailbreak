@rem Useful command line
@rem "-px <Key Container> <Out File> -pri"

@rem if the key container is in the user store use
@rem "-px <Key Container> <Out File> -pri -pku"

cd %~dp0\binaries
@jailbreak32.exe %WINDIR%\Microsoft.NET\Framework\v2.0.50727\aspnet_regiis.exe -px %*
