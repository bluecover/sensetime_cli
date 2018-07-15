package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/bluecover/sensetime_cli/sensetime"
	"github.com/spf13/viper"
)

func initConfig() {
	configPath := os.Getenv("CONFIG_PATH")
	if len(configPath) == 0 {
		configPath = "./config"
	}

	viper.AddConfigPath(configPath)
	viper.SetConfigName("identify")
	err := viper.ReadInConfig()
	if err != nil {
		panic(fmt.Errorf("Can not read config file: %s \n", err))
	}

	viper.AutomaticEnv()
	viper.SetEnvPrefix("identify")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
}

func respond(w http.ResponseWriter, r *http.Request, status int, data interface{}) error {
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return err
	}
	w.WriteHeader(status)
	if _, err := io.Copy(w, &buf); err != nil {
		return err
	}
	return nil
}

type HandlerFunc func(w http.ResponseWriter, r *http.Request)

func middleware_identify_liveness(sensetimeClient *sensetime.Client) HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}

		livenessID := r.FormValue("liveness_id")
		IDNumber := r.FormValue("id_number")
		realname := r.FormValue("realname")
		if len(livenessID) == 0 || len(IDNumber) == 0 || len(realname) == 0 {
			respond(w, r, http.StatusBadRequest, map[string]interface{}{"msg": "invalid parameter"})
			return
		}

		result, err := sensetimeClient.VerifyIDnumberByLiveness(livenessID, IDNumber, realname)
		if err != nil {
			respond(w, r, http.StatusInternalServerError, map[string]interface{}{"msg": err.Error()})
			return
		}
		respond(w, r, http.StatusOK, result)
	}
}

func middleware_identify_validity(sensetimeClient *sensetime.Client) HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}

		IDNumber := r.FormValue("id_number")
		realname := r.FormValue("realname")
		if len(IDNumber) == 0 || len(realname) == 0 {
			respond(w, r, http.StatusBadRequest, map[string]interface{}{"msg": "invalid parameter"})
			return
		}

		result, err := sensetimeClient.VerifyIDnumberValidity(IDNumber, realname)
		if err != nil {
			respond(w, r, http.StatusInternalServerError, map[string]interface{}{"msg": err.Error()})
			return
		}
		respond(w, r, http.StatusOK, result)
	}
}

func main() {
	initConfig()

	sensetimeClient := sensetime.NewClient()

	http.HandleFunc("/identify/liveness", middleware_identify_liveness(sensetimeClient))
	http.HandleFunc("/identify/validity", middleware_identify_validity(sensetimeClient))

	addr := fmt.Sprintf("%s:%d", viper.GetString("server.addr"), viper.GetInt("server.port"))
	log.Println("ListenAndServe", addr)
	err := http.ListenAndServe(addr, nil)
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}
