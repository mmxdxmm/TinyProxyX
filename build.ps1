# TinyProxy X - hand rolled build (aapt2 + javac + d8 + zipalign + apksig)
# Everything runs from ASCII-only paths: aapt2 chokes on non-ASCII input paths.
$ErrorActionPreference = 'Stop'
$proj = Split-Path -Parent $MyInvocation.MyCommand.Path
$base = Split-Path $proj -Parent
$tools = Join-Path $proj 'tools'
if (-not (Test-Path $tools)) { $tools = Join-Path $base 'tools' }
$ws = Split-Path $base -Parent
if ($env:TPX_WORKSPACE) { $ws = $env:TPX_WORKSPACE }
$sdk = Join-Path $ws 'tpx-toolchain'
$stage = Join-Path $ws 'tpx-stage'
# 上一轮 stage 里的 classes.jar 可能被文件系统权限卡住删不掉，用 TPX_STAGE 指个新目录绕开
if ($env:TPX_STAGE) { $stage = $env:TPX_STAGE }
$build = Join-Path $stage 'build'
# 版本号从 AndroidManifest 读，别再手写死在脚本里
$ver = '0.0.0'
$mf = Join-Path $proj 'AndroidManifest.xml'
if (Test-Path $mf) {
    $mm = Select-String -Path $mf -Pattern 'versionName="([^"]+)"' | Select-Object -First 1
    if ($mm) { $ver = $mm.Matches[0].Groups[1].Value }
}
$vcode = '1'
if (Test-Path $mf) {
    $mc = Select-String -Path $mf -Pattern 'versionCode="(\d+)"' | Select-Object -First 1
    if ($mc) { $vcode = $mc.Matches[0].Groups[1].Value }
}
$py = $env:TPX_PYTHON
if (-not $py) {
    $cmd = Get-Command python -ErrorAction SilentlyContinue
    if ($cmd) { $py = $cmd.Source }
}
if (-not $py -or -not (Test-Path $py)) { throw 'python not found; set TPX_PYTHON to python.exe' }

function Find-Tool($name) {
    $r = Get-ChildItem -Path $sdk -Recurse -Filter $name -ErrorAction SilentlyContinue |
        Sort-Object FullName | Select-Object -First 1
    if ($r) { return $r.FullName } else { return $null }
}

Write-Host "== toolchain"
$javac = Find-Tool 'javac.exe'
if (-not $javac) { throw "javac not found under $sdk" }
$jdkHome = Split-Path (Split-Path $javac -Parent) -Parent
$env:JAVA_HOME = $jdkHome
$env:PATH = "$jdkHome\bin;$env:PATH"
Write-Host "JDK  : $jdkHome"
$androidJar = Find-Tool 'android.jar'
if (-not $androidJar) { throw "android.jar not found" }
Write-Host "SDK  : $androidJar"
$aapt2 = Find-Tool 'aapt2.exe'
if (-not $aapt2) { throw "aapt2 not found" }
Write-Host "AAPT2: $aapt2"
$d8bat = Find-Tool 'd8.bat'
$r8jar = Find-Tool 'r8.jar'
if (-not $d8bat -and -not $r8jar) { throw "d8/r8 not found" }
$apsigner = Find-Tool 'apksigner.bat'
$apksigjar = Find-Tool 'apksig.jar'
$zipalign = Find-Tool 'zipalign.exe'
# hev 的 JNI 绑定（hev.htproxy.TProxyService）现在直接在 src/hev 里，不再吃 hevaar\classes.jar：
# 两边同时进 d8 会报 duplicate class。
$hevJar = $null

Write-Host "== stage -> $stage"
if (Test-Path $stage) { Remove-Item $stage -Recurse -Force }
New-Item -ItemType Directory -Path $stage | Out-Null
foreach ($item in @('res', 'src', 'assets', 'jniLibs')) {
    $srcPath = Join-Path $proj $item
    if (Test-Path $srcPath) {
        Copy-Item -Path $srcPath -Destination (Join-Path $stage $item) -Recurse -Force
    }
}
Copy-Item -Path (Join-Path $proj 'AndroidManifest.xml') -Destination $stage -Force
New-Item -ItemType Directory -Path $build | Out-Null
New-Item -ItemType Directory -Path "$build\classes" | Out-Null
New-Item -ItemType Directory -Path "$build\dex" | Out-Null

Write-Host "== aapt2 compile"
& $aapt2 compile --dir "$stage\res" -o "$build\res.zip"
if ($LASTEXITCODE -ne 0) { throw "aapt2 compile failed" }

Write-Host "== aapt2 link"
& $aapt2 link -o "$build\base.apk" -I $androidJar --manifest "$stage\AndroidManifest.xml" `
    -R "$build\res.zip" -A "$stage\assets" --min-sdk-version 26 --target-sdk-version 34 `
    --version-code $vcode --version-name $ver --auto-add-overlay
if ($LASTEXITCODE -ne 0) { throw "aapt2 link failed" }

Write-Host "== javac"
$srcs = @(Get-ChildItem -Path "$stage\src" -Recurse -Filter *.java | ForEach-Object { $_.FullName })
Write-Host "   sources: $($srcs.Count)"
& $javac --release 11 -encoding UTF-8 -nowarn -classpath $androidJar -d "$build\classes" $srcs
if ($LASTEXITCODE -ne 0) { throw "javac failed" }

Write-Host "== d8"
# one jar instead of N .class args: the class list outgrew the Windows command line
$injar = "$build\classes.jar"
$jarExe = Join-Path $jdkHome 'bin\jar.exe'
if (Test-Path $injar) { Remove-Item $injar -Force }
& $jarExe -cf $injar -C "$build\classes" .
if ($LASTEXITCODE -ne 0) { throw "jar failed" }
$d8in = @($injar)
Write-Host "   inputs: $($d8in.Count) jar(s)"
if ($d8bat) {
    & $d8bat --min-api 26 --lib $androidJar --output "$build\dex" $d8in
} else {
    & java -cp $r8jar com.android.tools.r8.D8 --min-api 26 --lib $androidJar --output "$build\dex" $d8in
}
if ($LASTEXITCODE -ne 0) { throw "d8 failed" }
if (-not (Test-Path "$build\dex\classes.dex")) { throw "no classes.dex" }

Write-Host "== package"
& $py (Join-Path $tools 'zipadd.py') "$build\base.apk" "$build\dex\classes.dex" "$stage\jniLibs" "$build\packed.apk"
if ($LASTEXITCODE -ne 0) { throw "packaging failed" }

$apk = "$build\packed.apk"
if ($zipalign) {
    Write-Host "== zipalign"
    & $zipalign -f -p 4 $apk "$build\aligned.apk"
    if ($LASTEXITCODE -eq 0) { $apk = "$build\aligned.apk" }
}

Write-Host "== sign"
$ks = Join-Path $ws 'tpx-debug.keystore'
if (-not (Test-Path $ks)) {
    Write-Host "   generating keystore"
    & keytool -genkeypair -keystore $ks -storetype PKCS12 -storepass android -keypass android `
        -alias tinyproxy -keyalg RSA -keysize 2048 -validity 10000 `
        -dname "CN=TinyProxy X, OU=dev, O=lcs, L=CN, S=CN, C=CN"
    if ($LASTEXITCODE -ne 0) { throw "keytool failed" }
}
$final = "$build\TinyProxyX-$ver.apk"
if ($apsigner) {
    & $apsigner sign --ks $ks --ks-pass pass:android --key-pass pass:android --out $final $apk
    if ($LASTEXITCODE -ne 0) { throw "apksigner failed" }
} else {
    if (-not (Test-Path "$build\signer")) { New-Item -ItemType Directory "$build\signer" | Out-Null }
    & javac -cp $apksigjar -d "$build\signer" (Join-Path $tools 'Sign.java')
    if ($LASTEXITCODE -ne 0) { throw "signer compile failed" }
    & java -cp "$apksigjar;$build\signer" Sign $apk $final $ks android tinyproxy
    if ($LASTEXITCODE -ne 0) { throw "signing failed" }
}

New-Item -ItemType Directory -Force -Path (Join-Path $proj 'build') | Out-Null
Copy-Item $final (Join-Path $proj "build\TinyProxyX-$ver.apk") -Force
Write-Host ""
Write-Host "BUILD OK: $final"
Write-Host ("SIZE: {0:N1} MB" -f ((Get-Item $final).Length / 1MB))

