import {
  app
} from 'electron';
import updater from './updater';
import {
  dialog,
  shell
} from 'electron';
import {
  BrowserWindow
} from 'electron';
import path from 'path';
import fs from 'fs';
import mkpath from 'mkpath';
import config from 'dripcap/config';
import rimraf from 'rimraf';
import childProcess from 'child_process';

mkpath.sync(config.userPackagePath);
mkpath.sync(config.profilePath);

var Session = null;
try {
  Session = require('paperfilter').Session;
} catch (e) {
  console.warn(e);
}

if (process.platform === 'darwin' && !Session.permission) {
  let helperPath = path.join(__dirname, '../../../Frameworks/Dripcap Helper Installer.app');
  let helperAppPath = path.join(helperPath, '/Contents/MacOS/Dripcap Helper Installer');
  try {
    childProcess.execFileSync(helperAppPath);
  } catch (e) {
    console.warn(e);
  }
}

class Dripcap {
  constructor() {
    this._indicator = 0;
  }

  checkForUpdates() {
    let {
      autoUpdater
    } = require('electron');
    autoUpdater.on('error', e => {
        console.warn(e.toString());
        return setTimeout(this.checkForUpdates, 60 * 60 * 1000 * 4);
      })
      .on('checking-for-update', () => console.log('Checking for update'))
      .on('update-available', () => console.log('Update available'))
      .on('update-not-available', () => {
        console.log('Update not available');
        return setTimeout(this.checkForUpdates, 60 * 60 * 1000 * 4);
      })
      .on('update-downloaded', function() {
        let index = dialog.showMessageBox({
          message: "Updates Available",
          detail: "Do you want to install a new version now?",
          buttons: ["Restart and Install", "Not Now"]
        });

        if (index === 0) {
          return autoUpdater.quitAndInstall();
        }
      });

    return updater.createServer(function(url) {
      autoUpdater.setFeedURL(url);
      return autoUpdater.checkForUpdates();
    });
  }

  newWindow() {
    let options = {
      width: 1200,
      height: 800,
      show: false,
      titleBarStyle: 'hidden-inset'
    };

    let mainWindow = new BrowserWindow(options);
    mainWindow.loadURL(`file://${__dirname}/../render.html`);
    mainWindow.webContents.on('did-finish-load', () => {
      mainWindow.show();
    });
  }
}

const dripcap = new Dripcap();

app.on('quit', () => {
  if (Session != null) {
    rimraf(Session.tmpDir, () => {});
  }
});

app.on('window-all-closed', () => app.quit());

app.on('ready', function() {
  if (process.platform === 'darwin') {
    dripcap.checkForUpdates();
  }
  if (process.platform === 'win32' && process.env['DRIPCAP_UI_TEST'] == null) {
    let wpcap = false;
    for (let dir of process.env.Path.split(';')) {
      try {
        fs.accessSync(path.join(dir, 'wpcap.dll'));
        wpcap = true;
        break;
      } catch (e) {}
    }
    if (!wpcap) {
      let button = dialog.showMessageBox({
        title: "WinPcap required",
        message: "Dripcap depends on WinPcap.\nPlease install WinPcap on your system.",
        buttons: ["Download WinPcap", "Quit"]
      });
      if (button === 0) {
        shell.openExternal('https://www.winpcap.org/install/');
      }
      app.quit();
    }
  }
  return dripcap.newWindow();
});
