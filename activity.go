// Package token implements getting a token from TIBCO Cloud Mashery
package token

import (
	// b64 "encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/TIBCOSoftware/flogo-lib/core/activity"
	"github.com/TIBCOSoftware/flogo-lib/logger"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
)

const (
	ivgrantType    = "grantType"
	ivUsername     = "username"
	ivPassword     = "password"
	ivClientId     = "clientid"
	ivClientSecret = "clientsecret"
	ivtokenUrl     = "tokenURL"
	ovToken        = "accesstoken"
	ovTokenType    = "tokentype"
	ovInstance_Url = "instance_url"
	ovId           = "id"
	ovIssued_at    = "issued_at"
	ovSignature    = "signature"
)

// log is the default package logger
var log = logger.GetLogger("activity-token")

// MyActivity is a stub for your Activity implementation
type MyActivity struct {
	metadata *activity.Metadata
}

// NewActivity creates a new activity
func NewActivity(metadata *activity.Metadata) activity.Activity {
	return &MyActivity{metadata: metadata}
}

// Metadata implements activity.Activity.Metadata
func (a *MyActivity) Metadata() *activity.Metadata {
	return a.metadata
}

// Eval implements activity.Activity.Eval
func (a *MyActivity) Eval(context activity.Context) (done bool, err error) {

	// Get the user provided data
	tokenURL := context.GetInput(ivtokenUrl).(string)
	username := context.GetInput(ivUsername).(string)
	password := context.GetInput(ivPassword).(string)
	clientid := context.GetInput(ivClientId).(string)
	clientsecret := context.GetInput(ivClientSecret).(string)
	grantType := context.GetInput(ivgrantType).(string)
	// auth := context.GetInput(ivBasicAuth).(string)
	// encodedAuth := b64.StdEncoding.EncodeToString([]byte(auth))

	queryParam := url.Values{
	  //"tokenURL":    {tokenURL},
		"grant_type":    {grantType},
		"client_id":     {clientid},
		"client_secret": {clientsecret},
		"username":      {username},
		"password":      {password},
	}

	body := strings.NewReader(queryParam.Encode())

	// Get the token from TIBCO Cloud Mashery
	//payload := strings.NewReader(fmt.Sprintf("grant_type=%s&username=%s&password=%s&clientid=%s&clientsecret=%s", grantType, username, password, clientid, clientsecret))

	req, err := http.NewRequest("POST", tokenURL, body)
	if err != nil {
		return false, err
	}

	req.Header.Add("content-type", "application/x-www-form-urlencoded")
	// req.Header.Add("authorization", fmt.Sprintf("Basic %s", encodedAuth))

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return false, err
	}

	defer res.Body.Close()

	resPonsebody, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return false, err
	}

	fmt.Println(string(resPonsebody))
	// Set the output value in the context
	var data map[string]interface{}
	if err := json.Unmarshal(resPonsebody, &data); err != nil {
		return false, err
	}
	context.SetOutput(ovInstance_Url, data["instance_url"])
	context.SetOutput(ovId, data["id"])
	context.SetOutput(ovIssued_at, data["issued_at"])
	context.SetOutput(ovToken, data["access_token"])
	context.SetOutput(ovTokenType, data["token_type"])
	context.SetOutput(ovSignature, data["signature"])

	return true, nil
}
