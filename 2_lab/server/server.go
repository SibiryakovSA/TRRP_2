package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"strings"

	"github.com/jackc/pgx/v4"
)

type message struct {
	Key     []byte
	Message []byte
}

func decryptKey(ciphertext []byte, priv *rsa.PrivateKey) []byte {
	hash := sha256.New()
	plaintext, err := rsa.DecryptOAEP(hash, rand.Reader, priv, ciphertext, nil)
	if err != nil {
		fmt.Println(err)
	}
	return plaintext
}

func pkcs5UnPadding(src []byte) []byte {
	length := len(src)
	unpadding := int(src[length-1])
	return src[:(length - unpadding)]
}
func decryptMessage(key, iv, cipherText []byte) ([]byte, error) {

	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockMode := cipher.NewCBCDecrypter(block, iv)
	origData := make([]byte, len(cipherText))
	blockMode.CryptBlocks(origData, cipherText)
	origData = pkcs5UnPadding(origData)
	return origData, nil
}

func handleConnection(conn net.Conn, connString string) error {
	defer conn.Close()

	//определяем подключение к бд
	dbConn, err := pgx.Connect(context.Background(), connString)
	if err != nil {
		fmt.Println(err)
		return err
	}
	defer dbConn.Close(context.Background())

	//получаем закрытый и открытый ключ
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Println(err)
		return err
	}

	//получаем открытый ключ
	pubKeyByte, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		fmt.Println(err)
		return err
	}

	//получаем открытый ключ в виде строки
	pubKeyBase64 := base64.StdEncoding.EncodeToString(pubKeyByte)
	conn.Write([]byte(pubKeyBase64 + "\n"))

	first := true
	for {
		receivedString, _ := bufio.NewReader(conn).ReadString('\n')
		messageByte, _ := base64.StdEncoding.DecodeString(receivedString)

		tempByte := bytes.NewBuffer(messageByte)
		enc := gob.NewDecoder(tempByte)

		var receivedMessage message
		err = enc.Decode(&receivedMessage)
		if err != nil {
			return err
		}

		desKey := decryptKey(receivedMessage.Key, key)
		mes, err := decryptMessage(desKey, desKey, receivedMessage.Message)

		if first {
			fmt.Printf("Хэш симметричного ключа  = %x\n", md5.Sum(desKey))
			fmt.Printf("Хэш асимметричного ключа = %x\n", md5.Sum([]byte(fmt.Sprintf("%v", key))))
			first = false
		}

		inputData := strings.Split(string(mes), ";")
		name := strings.TrimSpace(inputData[1])
		department := strings.TrimSpace(inputData[2])
		universityName := strings.TrimSpace(inputData[3])
		cityName := strings.TrimSpace(inputData[4])
		var employeeRole string
		if len(inputData) == 5 {
			employeeRole = ""
		} else {
			employeeRole = strings.TrimSpace(inputData[5])
		}

		cityId := -1
		err = dbConn.QueryRow(context.Background(), "select id from city where name = $1;", cityName).Scan(&cityId)
		if err == pgx.ErrNoRows {
			dbConn.QueryRow(context.Background(), "insert into city(name) values ($1) returning id", cityName).Scan(&cityId)
		}

		universityId := -1
		err = dbConn.QueryRow(context.Background(), "select id from university where name = $1 and cityId = $2;", universityName, cityId).Scan(&universityId)
		if err == pgx.ErrNoRows {
			dbConn.QueryRow(context.Background(), "insert into university(name, cityId) values ($1, $2) returning id", universityName, cityId).Scan(&universityId)
		}

		departmentId := -1
		err = dbConn.QueryRow(context.Background(), "select id from department where name = $1 and universityId = $2;", department, universityId).Scan(&departmentId)
		if err == pgx.ErrNoRows {
			dbConn.QueryRow(context.Background(), "insert into department(name, universityId) values ($1, $2) returning id", department, universityId).Scan(&departmentId)
		}

		//если должности нет, это студент
		if employeeRole == ""{
			studentId := -1
			err = dbConn.QueryRow(context.Background(), "select id from students where name = $1 and departmentId = $2;", name, departmentId).Scan(&studentId)
			if err == pgx.ErrNoRows {
				dbConn.QueryRow(context.Background(), "insert into students(name, departmentId) values ($1, $2) returning id", name, departmentId).Scan(&studentId)
			}
		} else {
			employeeId := -1
			err = dbConn.QueryRow(context.Background(), "select id from researchEmployee where name = $1 and post = $2;", name, employeeRole).Scan(&employeeId)
			if err == pgx.ErrNoRows {
				dbConn.QueryRow(context.Background(), "insert into researchEmployee(name, post) values ($1, $2) returning id", name, employeeRole).Scan(&employeeId)
			}

			err = dbConn.QueryRow(context.Background(), "select * from DepartmentEmployee where departmentId = $1 and employeeId = $2", departmentId, employeeId).Scan()
			if err == pgx.ErrNoRows {
				dbConn.QueryRow(context.Background(), "insert into DepartmentEmployee(departmentId, employeeId) values ($1, $2)", departmentId, employeeId).Scan()
			}
		}

		conn.Write([]byte("\n"))
	}
}

type config struct {
	ConnectionString string `json:"connectionString"`
	ListenPort       string `json:"listenPort"`
}

func main() {

	dat, err := ioutil.ReadFile("server/config.txt")
	if err != nil {
		fmt.Println("Ошибка в чтении файла конфигурации")
		return
	}
	var config1 config
	err = json.Unmarshal(dat, &config1)
	if err != nil {
		fmt.Println("Ошибка в инициализации конфигурации")
		return
	}

	// Устанавливаем прослушивание порта
	ln, err := net.Listen("tcp", config1.ListenPort)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer ln.Close()

	fmt.Println("Ожидание подключения ...")
	for {
		conn, err := ln.Accept()
		if err != nil {
			fmt.Println(err)
			conn.Close()
			continue
		}
		go handleConnection(conn, config1.ConnectionString)
	}
}
