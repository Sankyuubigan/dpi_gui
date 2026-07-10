const fs = require('fs');
const path = require('path');
const { spawn, execSync } = require('child_process');
const { readVersion } = require('./version.cjs');

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

// Принудительно останавливаем процесс перед сборкой (как в build.cjs),
// чтобы tauri-build смог перезаписать занятые файлы (os error 32).
function killProcess(processName) {
    try {
        execSync(`taskkill /f /im ${processName}`, { stdio: 'ignore', timeout: 5000 });
        console.log(`  Останавливаем запущенный процесс: ${processName}`);
    } catch (e) {}
}

function formatBytes(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / 1024 / 1024).toFixed(1) + ' MB';
}

// Временный конфиг-оверрайд, включающий генерацию артефактов обновления.
// Обычная build.bat-сборка его НЕ использует, поэтому не требует ключ подписи.
function writeUpdaterOverride() {
    const override = {
        bundle: { createUpdaterArtifacts: true }
    };
    const out = path.join(scriptDir, 'src-tauri', 'release.build.conf.json');
    fs.writeFileSync(out, JSON.stringify(override, null, 2), 'utf8');
    return out;
}

// Подставляет публичный ключ обноватора в tauri.conf.json (plugins.updater.pubkey),
// чтобы собранное приложение могло проверять подпись установщика.
function injectPubkey(pubkey) {
    const confPath = path.join(scriptDir, 'src-tauri', 'tauri.conf.json');
    const conf = JSON.parse(fs.readFileSync(confPath, 'utf8'));
    conf.plugins = conf.plugins || {};
    conf.plugins.updater = conf.plugins.updater || {};
    conf.plugins.updater.pubkey = pubkey;
    fs.writeFileSync(confPath, JSON.stringify(conf, null, 2), 'utf8');
}

async function main() {
    try {
        // 0. Останавливаем мешающие процессы
        console.log('========================================');
        console.log('  Останавливаем мешающие процессы перед сборкой...');
        killProcess('winws.exe');
        killProcess('dpi_gui.exe');
        console.log('========================================');

        // 1. Определение версии релиза. Билдер (build.cjs) уже инкрементировал
        //    номер сборки при каждой сборке, поэтому релизим ИМЕННО ту версию,
        //    что собрана (без повторного бампа — иначе версии разойдутся).
        console.log('\n========================================');
        console.log('[1/9] Opredelenie versii reliza...');
        const version = readVersion(scriptDir);
        console.log(`Versiya reliza: ${version}`);

        // 2. Ключи подписи (приватный ключ, публичный ключ, пароль)
        console.log('\n========================================');
        console.log('[2/9] Poisk klyuchey podpisi...');
        const keysDir = process.env.TAURI_SIGNED_KEYS_DIR
            || 'D:\\Projects\\docusaurus-starter\\docs\\Sega Mega Note\\Моя картотека\\software\\настройки\\tauri_signed_keys';
        const keyPath = path.join(keysDir, 'tauri.key');
        const pubKeyPath = path.join(keysDir, 'tauri.key.pub');
        const passwordPath = path.join(keysDir, 'TAURI_KEY_PASSWORD.txt');

        if (!fs.existsSync(keyPath)) {
            throw new Error(
                `Приватный ключ НЕ НАЙДЕН:\n${keyPath}\n\nУбедитесь, что папка с ключами существует, ` +
                `либо задайте её через переменную окружения TAURI_SIGNED_KEYS_DIR.`
            );
        }
        if (!fs.existsSync(pubKeyPath)) {
            throw new Error(`Публичный ключ НЕ НАЙДЕН:\n${pubKeyPath}`);
        }
        console.log('🔑 Ключи найдены.');

        const keyContent = fs.readFileSync(keyPath, 'utf8').trim();
        const pubkey = fs.readFileSync(pubKeyPath, 'utf8').trim();
        const password = fs.existsSync(passwordPath)
            ? fs.readFileSync(passwordPath, 'utf8').trim()
            : (process.env.TAURI_SIGNING_PRIVATE_KEY_PASSWORD || '123');

        process.env.TAURI_SIGNING_PRIVATE_KEY = keyContent;
        process.env.TAURI_SIGNING_PRIVATE_KEY_PASSWORD = password;

        // Подставляем публичный ключ в конфиг, чтобы собранное приложение
        // могло проверять подпись установщика.
        injectPubkey(pubkey);
        console.log('  Публичный ключ подставлен в tauri.conf.json.');

        // 3. npm install
        console.log('\n========================================');
        console.log('[3/9] Ustanovka zavisimostey Node.js...');
        await runCommand('npm', ['install']);

        // 4. Подготовка bin/ (sidecar-бинари)
        console.log('\n========================================');
        console.log('[4/9] Podgotovka sidecars (bin/)...');
        const binDir = path.join(scriptDir, 'bin');
        if (!fs.existsSync(binDir)) {
            console.warn('  WARNING: bin/ not found. Place winws.exe, WinDivert64.sys and .bin files there.');
        } else {
            console.log('  bin/ folder found:', fs.readdirSync(binDir).join(', '));
        }

        // 5. Проверка иконок
        console.log('\n========================================');
        console.log('[5/9] Proverkaikonok...');
        const iconPath = path.join(scriptDir, 'src-tauri', 'icons', 'icon.ico');
        if (fs.existsSync(iconPath)) console.log('  icon.ico is valid.');
        else console.warn('  icon.ico not found in src-tauri/icons/');

        // 6. Сборка с подписью (через override createUpdaterArtifacts)
        console.log('\n========================================');
        console.log('[6/9] Sbornya prilozheniya Tauri (release + podpis)...');

        const overridePath = writeUpdaterOverride();
        process.env.RUSTFLAGS = '-Ctarget-feature=+crt-static';

        let buildOk = false;
        try {
            await runCommand('npx', ['tauri', 'build', '--config', overridePath]);
            buildOk = true;
        } finally {
            try { fs.unlinkSync(overridePath); } catch (e) {}
        }
        if (!buildOk) throw new Error('Tauri build failed');

        // Копируем sidecar-бинари в release/bin (как в build.cjs)
        const releaseDir = path.join(scriptDir, 'src-tauri', 'target', 'release');
        const releaseBinDir = path.join(releaseDir, 'bin');
        if (fs.existsSync(binDir) && fs.existsSync(releaseDir)) {
            if (!fs.existsSync(releaseBinDir)) fs.mkdirSync(releaseBinDir, { recursive: true });
            for (const file of fs.readdirSync(binDir)) {
                try { fs.copyFileSync(path.join(binDir, file), path.join(releaseBinDir, file)); }
                catch (e) { console.warn(`  Failed to copy ${file}`); }
            }
            console.log('  Sidecars copied to release/bin/');
        }

        // 7. Генерация latest.json
        console.log('\n========================================');
        console.log('[7/9] Generaciya latest.json...');

        const nsisDir = path.join(scriptDir, 'src-tauri', 'target', 'release', 'bundle', 'nsis');
        if (!fs.existsSync(nsisDir)) throw new Error('NSIS bundle dir не найден! Сборка не удалась.');

        const exeFiles = fs.readdirSync(nsisDir).filter(f => f.endsWith('-setup.exe')).sort();
        const exeFile = exeFiles[exeFiles.length - 1];
        if (!exeFile) throw new Error('-setup.exe не найден в ' + nsisDir);

        const sigFile = fs.readdirSync(nsisDir).find(f => f === `${exeFile}.sig`);
        if (!sigFile) throw new Error(`${exeFile}.sig не найден! Сборка не подписана.`);

        const signature = fs.readFileSync(path.join(nsisDir, sigFile), 'utf8').trim();
        const encodedExeName = encodeURIComponent(exeFile);
        const updateJson = {
            version: version,
            notes: `Обновление DPI GUI до версии ${version}`,
            pub_date: new Date().toISOString(),
            platforms: {
                "windows-x86_64": {
                    signature: signature,
                    url: `https://github.com/Sankyuubigan/dpi_gui/releases/download/v${version}/${encodedExeName}`
                }
            }
        };
        fs.writeFileSync(path.join(scriptDir, 'latest.json'), JSON.stringify(updateJson, null, 2), 'utf8');
        console.log(`latest.json сгенерирован. Установщик: ${exeFile}`);

        // 8. Коммит и пуш изменённой версии в репозиторий
        console.log('\n========================================');
        console.log('[8/9] Kommit i push versii v repo...');
        try {
            const status = execSync('git status --porcelain src-tauri/tauri.conf.json src-tauri/Cargo.toml', { encoding: 'utf8', cwd: scriptDir });
            if (status.trim()) {
                execSync('git add src-tauri/tauri.conf.json src-tauri/Cargo.toml', { stdio: 'inherit', cwd: scriptDir });
                execSync(`git commit -m "Release v${version}"`, { stdio: 'inherit', cwd: scriptDir });
                console.log('  Изменения версии закоммичены.');
            } else {
                console.log('  Версия уже закоммичена, коммит не нужен.');
            }
            execSync('git push', { stdio: 'inherit', cwd: scriptDir });
            console.log('✅ Изменения запушены в репозиторий.');
        } catch (e) {
            console.error('\n[ОШИБКА] Не удалось запушить в репозиторий:', e.message);
            console.error('Продолжаю создание релиза, но версия в репе может не совпасть!');
        }

        // 9. Публикация на GitHub
        console.log('\n========================================');
        console.log('[9/9] Publikaciya reliza na GitHub...');

        console.log('Проверка авторизации GitHub CLI...');
        try {
            execSync('gh auth status', { stdio: 'pipe', cwd: scriptDir });
            console.log('✅ Авторизация пройдена!');
        } catch (e) {
            console.error('\n[ОШИБКА] Вы не авторизованы в GitHub CLI!');
            console.error('Выполните: gh auth login');
            process.exit(1);
        }

        const tag = `v${version}`;
        const exePathFull = path.join(nsisDir, exeFile);
        const sigPathFull = path.join(nsisDir, sigFile);
        const latestJsonPath = path.join(scriptDir, 'latest.json');
        const exeSize = fs.statSync(exePathFull).size;

        console.log(`\n📦 Файлы для загрузки:`);
        console.log(`   ${exeFile} (${formatBytes(exeSize)})`);
        console.log(`   ${sigFile}`);
        console.log(`   latest.json`);
        console.log(`\n🚀 Загрузка на GitHub (${tag})...`);

        await new Promise((resolve, reject) => {
            const cmd = `gh release create ${tag} "${exePathFull}" "${sigPathFull}" "${latestJsonPath}" --title "${tag}" --notes "Автоматический релиз DPI GUI ${tag}"`;
            const proc = spawn(cmd, [], { stdio: 'inherit', shell: true, cwd: scriptDir });
            proc.on('close', (code) => {
                if (code === 0) resolve();
                else reject(new Error(`gh release create завершился с кодом ${code}`));
            });
        });

        console.log('\n========================================');
        console.log(`✅ Релиз ${tag} УСПЕШНО ОПУБЛИКОВАН!`);
        console.log('Пользователи смогут обновиться через вкладку «О программе».');

    } catch (e) {
        console.error('\n[ОШИБКА]', e.message);
        process.exit(1);
    }
}

main();
