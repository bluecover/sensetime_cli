package sensetime

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/parnurzeal/gorequest"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
)

type APIURL struct {
	ValidityIDNumberVerification string
	LivenessIDnumberVerification string
	IdentityIDNumberVerification string
	ResourceImageURL             string
}

type Client struct {
	APIKey     string
	APISecrect string
	APIURL     APIURL
}

// VerifyResult represents verification result from SenseTime API.
type VerifyResult struct {
	RequestID         string  `json:"request_id"`
	Code              int64   `json:"code"`
	Validity          bool    `json:"validity"`
	VerificationScore float64 `json:"verification_score"`
	Message           string  `json:"message"`
}

// UploadResult represents resource upload result from SenseTime API.
type UploadResult struct {
	RequestID string `json:"request_id"`
	Code      int64  `json:"code"`
	ID        string `json:"id"`
	Message   string `json:"message"`
}

func makeTimestamp() int64 {
	return time.Now().UnixNano() / int64(time.Millisecond)
}

func NewClient() *Client {
	config := viper.New()
	config.AddConfigPath("config")
	config.SetConfigName("sensetime")
	err := config.ReadInConfig()
	if err != nil {
		panic(err)
	}
	URLs := APIURL{
		ValidityIDNumberVerification: config.GetString("API.URL.validity_idnumber_verification"),
		LivenessIDnumberVerification: config.GetString("API.URL.liveness_idnumber_verification"),
		IdentityIDNumberVerification: config.GetString("API.URL.identity_idnumber_verification"),
		ResourceImageURL:             config.GetString("API.URL.resource_image_url"),
	}
	return &Client{
		APIKey:     config.GetString("API.key"),
		APISecrect: config.GetString("API.secret"),
		APIURL:     URLs,
	}
}

// BuildSignature builds a signature for SenseTime API.
//
//	用户自己生成 timestamp（Unix 时间戳;
//	生成随机数nonce(注：最好是32位的);
//		一）将timestamp、nonce、API_KEY 这三个字符串依据字符串首位字符的ASCII码进行升序排列，并join成一个字符串;
//		二）然后用API_SECRET对这个字符串做hamc-sha256 签名，以16进制编码;
//	将上述得到的签名结果作为 signature 的值，与 API_KEY, nonce, timestamp 一起放在HTTP HEADER 的 Authorization 中。
//
func (cli *Client) BuildSignature(timestamp string, nonce string) (string, error) {
	sorted := []string{cli.APIKey, timestamp, nonce}
	sort.Strings(sorted)
	joined := strings.Join(sorted, "")
	h := hmac.New(sha256.New, []byte(cli.APISecrect))
	io.WriteString(h, joined)
	hashedx := fmt.Sprintf("%x", h.Sum(nil))
	return hashedx, nil
}

// buildAuthorizationHeader builds Authorization header value for SenseTime API.
func (cli *Client) buildAuthorizationHeader() (string, error) {
	ruuid, err := uuid.NewRandom()
	if err != nil {
		return "", errors.Wrap(err, "uuid.NewRandom error")
	}
	nonce := ruuid.String()
	timestamp := fmt.Sprintf("%d", makeTimestamp())
	signature, err := cli.BuildSignature(timestamp, nonce)
	if err != nil {
		return "", err
	}
	value := fmt.Sprintf(strings.Join([]string{
		"key=%s",
		"timestamp=%s",
		"nonce=%s",
		"signature=%s",
	}, ","), cli.APIKey, timestamp, nonce, signature)
	return value, nil
}

func (cli *Client) decodeVerifyResponse(resp *http.Response, body string) (VerifyResult, error) {
	if resp.StatusCode != 200 {
		body, _ := ioutil.ReadAll(resp.Body)
		return VerifyResult{}, errors.Wrap(
			fmt.Errorf("response status: %d", resp.StatusCode), string(body),
		)
	}

	var r VerifyResult
	if err := json.Unmarshal([]byte(body), &r); err != nil {
		return VerifyResult{}, err
	}
	return r, nil
}

// VerifyIDnumberValidity invokes API: /validity/idnumber_verification
func (cli *Client) VerifyIDnumberValidity(IDNumber string, name string) (VerifyResult, error) {

	authHeaderValue, err := cli.buildAuthorizationHeader()
	if err != nil {
		return VerifyResult{}, err
	}

	formData := fmt.Sprintf(`{"idnumber":"%s", "name":"%s"}`, IDNumber, name)
	request := gorequest.New()
	resp, body, errs := request.Post(cli.APIURL.ValidityIDNumberVerification).
		Set("Authorization", authHeaderValue).
		Type("multipart").Send(formData).
		End()
	if len(errs) > 0 {
		return VerifyResult{}, errs[0]
	}

	result, err := cli.decodeVerifyResponse(resp, body)
	if err != nil {
		return VerifyResult{}, errors.Wrap(err, "VerifyIDnumberValidity")
	}
	return result, nil
}

// VerifyIDnumberByLiveness invokes API: /identity/liveness_idnumber_verification
func (cli *Client) VerifyIDnumberByLiveness(
	livenessID string, IDNumber string, name string) (VerifyResult, error) {

	authHeaderValue, err := cli.buildAuthorizationHeader()
	if err != nil {
		return VerifyResult{}, err
	}

	formData := fmt.Sprintf(`{"liveness_id":"%s", "idnumber":"%s", "name":"%s"}`,
		livenessID, IDNumber, name)
	request := gorequest.New()
	resp, body, errs := request.Post(cli.APIURL.LivenessIDnumberVerification).
		Set("Authorization", authHeaderValue).
		Type("multipart").Send(formData).
		End()
	if len(errs) > 0 {
		return VerifyResult{}, errs[0]
	}

	result, err := cli.decodeVerifyResponse(resp, body)
	if err != nil {
		return VerifyResult{}, errors.Wrap(err, "VerifyIDnumberByLiveness")
	}
	return result, nil
}

// VerifyIdnumberByImage invokes API: /identity/idnumber_verification
func (cli *Client) VerifyIdnumberByImage(
	imageID string, IDNumber string, name string) (VerifyResult, error) {

	authHeaderValue, err := cli.buildAuthorizationHeader()
	if err != nil {
		return VerifyResult{}, err
	}

	formData := fmt.Sprintf(`{"image_id":"%s", "idnumber":"%s", "name":"%s"}`,
		imageID, IDNumber, name)
	request := gorequest.New()
	resp, body, errs := request.Post(cli.APIURL.IdentityIDNumberVerification).
		Set("Authorization", authHeaderValue).
		Type("multipart").Send(formData).
		End()
	if len(errs) > 0 {
		return VerifyResult{}, errs[0]
	}

	result, err := cli.decodeVerifyResponse(resp, body)
	if err != nil {
		return VerifyResult{}, errors.Wrap(err, "VerifyIdnumberByImage")
	}
	return result, nil
}

// UploadImageByURL invokes API: /resource/image/url
func (cli *Client) UploadImageByURL(imageURL string) (UploadResult, error) {
	authHeaderValue, err := cli.buildAuthorizationHeader()
	if err != nil {
		return UploadResult{}, err
	}

	formData := fmt.Sprintf(`{"data":"%s"}`, imageURL)
	request := gorequest.New()
	resp, body, errs := request.Post(cli.APIURL.ResourceImageURL).
		Set("Authorization", authHeaderValue).
		Type("json").Send(formData).
		End()
	if len(errs) > 0 {
		return UploadResult{}, errs[0]
	}

	if resp.StatusCode != 200 {
		body, _ := ioutil.ReadAll(resp.Body)
		return UploadResult{}, errors.Wrap(
			fmt.Errorf("UploadImageByURL response status: %d", resp.StatusCode),
			string(body))
	}

	var r UploadResult
	if err := json.Unmarshal([]byte(body), &r); err != nil {
		return UploadResult{}, err
	}
	return r, nil
}
