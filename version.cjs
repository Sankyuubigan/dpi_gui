const fs = require('fs');
const path = require('path');

function readVersion(scriptDir) {
    const confPath = path.join(scriptDir, 'src-tauri', 'tauri.conf.json');
    const confText = fs.readFileSync(confPath, 'utf8');
    const match = confText.match(/"version"\s*:\s*"(\d+)\.(\d+)\.(\d+)"/);
    if (!match) throw new Error('Не удалось найти версию в tauri.conf.json');
    return `${match[1]}.${match[2]}.${match[3]}`;
}

// Единая логика автогенерации версии для ВСЕХ сборок (build.cjs и release.cjs).
// Схема YY.M.P:
//   YY — две последние цифры года
//   M  — месяц
//   P  — номер сборки через билдер (инкремент в рамках месяца, сброс в 1 при смене месяца)
// Возвращает новую версию и синхронно пишет её в tauri.conf.json и Cargo.toml.
function bumpVersion(scriptDir) {
    const confPath = path.join(scriptDir, 'src-tauri', 'tauri.conf.json');
    const cargoPath = path.join(scriptDir, 'src-tauri', 'Cargo.toml');

    let confText = fs.readFileSync(confPath, 'utf8');
    const match = confText.match(/"version"\s*:\s*"(\d+)\.(\d+)\.(\d+)"/);
    if (!match) throw new Error('Не удалось найти версию в tauri.conf.json');

    const oldMaj = match[1];
    const oldMin = match[2];
    const oldPat = parseInt(match[3], 10);

    const now = new Date();
    const newMaj = now.getFullYear().toString().slice(-2);
    const newMin = (now.getMonth() + 1).toString();
    const newPat = (oldMaj === newMaj && oldMin === newMin) ? oldPat + 1 : 1;

    const version = `${newMaj}.${newMin}.${newPat}`;

    confText = confText.replace(/"version"\s*:\s*".*?"/, `"version": "${version}"`);
    fs.writeFileSync(confPath, confText, 'utf8');

    let cargoText = fs.readFileSync(cargoPath, 'utf8');
    cargoText = cargoText.replace(/^version\s*=\s*".*?"/m, `version = "${version}"`);
    fs.writeFileSync(cargoPath, cargoText, 'utf8');

    return version;
}

module.exports = { readVersion, bumpVersion };
