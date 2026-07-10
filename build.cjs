const fs = require('fs');
const path = require('path');
const { spawn, execSync } = require('child_process');

const scriptDir = __dirname;

function runCommand(command, args = [], options = {}) {
    return new Promise((resolve, reject) => {
        const proc = spawn(command, args, { stdio: 'inherit', shell: true, cwd: scriptDir, ...options });
        proc.on('close', (code) => {
            if (code === 0) resolve();
            else reject(new Error(`Command exited with code ${code}`));
        });
    });
}

function checkDllDependencies(exePath) {
    try {
        const result = execSync(`powershell -NoProfile -Command "& { (Get-Item '${exePath}').VersionInfo | Format-List }"`, { encoding: 'utf8', timeout: 5000 });
        console.log(`  File: ${path.basename(exePath)}`);
    } catch (e) {}

    try {
        console.log('  Checking DLL imports...');
        execSync(`powershell -NoProfile -Command "$bytes = [System.IO.File]::ReadAllBytes('${exePath}'); $text = [System.Text.Encoding]::ASCII.GetString($bytes); $dlls = @(); $text -split '\\0' | % { if ($_ -match '^[a-zA-Z0-9_\\-\\.]+\\.dll$' -and $_.Length -gt 3) { $dlls += $_ } }; $dlls | Sort-Object -Unique"`, { encoding: 'utf8', timeout: 10000 });
    } catch (e) {
        console.log('  (DLL check skipped)');
    }
}

// Принудительно останавливаем процесс перед сборкой. Нужно, чтобы tauri-build
// мог перезаписать sidecar-бинари (winws.exe и др.) в target\release\bin\.
// Если процесс не запущен — execSync упадёт, поэтому ошибку глушим.
function killProcess(processName) {
    try {
        execSync(`taskkill /f /im ${processName}`, { stdio: 'ignore', timeout: 5000 });
        console.log(`  Останавливаем запущенный процесс: ${processName}`);
    } catch (e) {
        // процесс не запущен — это нормально, просто игнорируем
    }
}

async function main() {
    try {
        // Перед сборкой останавливаем запущенные копии, иначе tauri-build не
        // сможет перезаписать занятые файлы (os error 32: файл занят).
        console.log('========================================');
        console.log('  Останавливаем мешающие процессы перед сборкой...');
        killProcess('winws.exe');
        killProcess('dpi_gui.exe');
        console.log('========================================');

        const exeToBuild = path.join(scriptDir, 'src-tauri', 'target', 'release', 'dpi_gui.exe');

        console.log('========================================');
        console.log('[1/5] Installing Node.js dependencies...');
        await runCommand('npm', ['install']);

        console.log('\n========================================');
        console.log('[2/5] Preparing sidecars (bin/)...');
        const binDir = path.join(scriptDir, 'bin');
        if (!fs.existsSync(binDir)) {
            console.warn('  WARNING: bin/ folder not found in project root.');
            console.warn('  Place winws.exe, WinDivert64.sys and .bin files there.');
        } else {
            console.log('  bin/ folder found.');
            const files = fs.readdirSync(binDir);
            console.log(`  Files: ${files.join(', ')}`);
        }

        console.log('\n========================================');
        console.log('[3/5] Checking icons...');
        const iconPath = path.join(scriptDir, 'src-tauri', 'icons', 'icon.ico');
        if (fs.existsSync(iconPath)) {
            console.log('  icon.ico is valid.');
        } else {
            console.warn('  icon.ico not found in src-tauri/icons/');
        }

        console.log('\n========================================');
        console.log('[4/5] Building Tauri app...');

        const overridePath = path.join(scriptDir, 'src-tauri', 'tauri-dev-override.json');
        fs.writeFileSync(overridePath, JSON.stringify({ bundle: { active: false } }));

        process.env.RUSTFLAGS = '-Ctarget-feature=+crt-static';

        console.log('  Cleaning previous build artifacts...');
        const targetDir = path.join(scriptDir, 'src-tauri', 'target');
        if (fs.existsSync(path.join(targetDir, 'release', 'dpi_gui.exe'))) {
            try {
                fs.rmSync(path.join(targetDir, 'release', 'dpi_gui.exe'));
            } catch (e) {
                console.error('');
                console.error('  ⚠️  Не удалось удалить старый dpi_gui.exe — файл занят.');
                console.error('  ➡️  Закрой программу DPI GUI и повтори сборку.');
                console.error('');
                process.exit(1);
            }
        }

        let buildOk = false;
        try {
            await runCommand('npx', ['tauri', 'build', '--config', overridePath]);
            buildOk = true;
        } finally {
            try { fs.unlinkSync(overridePath); } catch (e) {}
        }

        if (!buildOk) {
            throw new Error('Tauri build failed');
        }

        const releaseDir = path.join(scriptDir, 'src-tauri', 'target', 'release');
        const releaseBinDir = path.join(releaseDir, 'bin');
        if (fs.existsSync(binDir) && fs.existsSync(releaseDir)) {
            if (!fs.existsSync(releaseBinDir)) fs.mkdirSync(releaseBinDir, { recursive: true });
            for (const file of fs.readdirSync(binDir)) {
                const src = path.join(binDir, file);
                const dst = path.join(releaseBinDir, file);
                try { fs.copyFileSync(src, dst); } catch (e) { console.warn(`  Failed to copy ${file}`); }
            }
            console.log('  Sidecars copied to release/bin/');
        }

        if (!fs.existsSync(exeToBuild)) {
            throw new Error('dpi_gui.exe not found! Build failed.');
        }

        const exeSize = fs.statSync(exeToBuild).size;
        console.log(`  EXE size: ${(exeSize / 1024 / 1024).toFixed(1)} MB`);

        console.log('  Verifying DLL dependencies...');
        checkDllDependencies(exeToBuild);

        console.log('\n========================================');
        console.log('[5/5] Build complete!');
        console.log(`  EXE: ${exeToBuild}`);

    } catch (e) {
        const msg = e.message || '';
        const isFileLocked = /os error 5|Отказано в доступе|failed to remove file|EBUSY|EPERM|EACCES/.test(msg);

        console.error('\n========================================');
        if (isFileLocked) {
            console.error('  ⚠️  Не удалось собрать — dpi_gui.exe всё ещё запущен.');
            console.error('  ➡️  Закрой программу DPI GUI и повтори сборку.');
        } else {
            console.error('ERROR:', msg);
        }
        console.error('========================================');
        process.exit(1);
    }
}

main();
