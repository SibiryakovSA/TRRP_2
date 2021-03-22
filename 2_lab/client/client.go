package main

import (
	"bufio"
	"bytes"
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/gob"
	"fmt"
	_ "github.com/mattn/go-sqlite3"
	"net"
	"os"
)

type message struct {
	Key     []byte
	Message []byte
}

func encryptKey(msg []byte, pub *rsa.PublicKey) []byte {
	hash := sha256.New()
	ciphertext, err := rsa.EncryptOAEP(hash, rand.Reader, pub, msg, nil)
	if err != nil {
		fmt.Println(err)
	}
	return ciphertext
}

func pkcs5Padding(src []byte, blockSize int) []byte {
	padding := blockSize - len(src)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}

func encryptMessage(key, iv, plainText []byte) ([]byte, error) {

	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockMode := cipher.NewCBCEncrypter(block, iv)
	origData := pkcs5Padding(plainText, block.BlockSize())
	encrypted := make([]byte, len(origData))
	blockMode.CryptBlocks(encrypted, origData)
	return encrypted, nil

}

func main() {
	desKey := []byte("rand8chr")
	iv := desKey[:des.BlockSize]

	dat, err := os.ReadFile("client/config.txt")
	if err != nil {
		fmt.Println("Ошибка в чтении файла конфигурации")
		return
	}

	// Подключаемся к сокету
	conn, err := net.Dial("tcp", string(dat))
	if err != nil {
		fmt.Println("Ошибка при подключении к серверу")
		return
	}

	pubKeyBase64, _ := bufio.NewReader(conn).ReadString('\n')
	pubKeyByte, _ := base64.StdEncoding.DecodeString(pubKeyBase64)
	key, _ := x509.ParsePKIXPublicKey(pubKeyByte)

	db, err := sql.Open("sqlite3", "client/db.sqlite")
	if err != nil {
		fmt.Println("Ошибка подключения к БД:\n", err)
		return
	}
	defer db.Close()
	rows, err := db.Query("select * from PeopleInUniversities")
	if err != nil {
		fmt.Println("Ошибка получения данных из БД:\n ", err)
		return
	}
	defer rows.Close()

	fmt.Printf("Хэш симметричного ключа  = %x\n", md5.Sum(desKey))
	fmt.Printf("Хэш асимметричного ключа = %x\n", md5.Sum([]byte(fmt.Sprintf("%x", key.(*rsa.PublicKey)))))

	for rows.Next() {
		var id, name, department, universityName, cityName, employeeRole string

		rows.Scan(&id, &name, &department, &universityName, &cityName, &employeeRole)
		textToSend := id + ";" +name + ";" + department + ";" + universityName + ";" + cityName + ";" + employeeRole

		var send message
		send.Key = encryptKey(desKey, key.(*rsa.PublicKey))

		encMessage, _ := encryptMessage(desKey, iv, []byte(textToSend))
		send.Message = encMessage

		var messageByte bytes.Buffer
		enc := gob.NewEncoder(&messageByte)
		err = enc.Encode(send)
		if err != nil {
			fmt.Println("Ошибка при энкоде:\n", err)
		}
		messageToSend := base64.StdEncoding.EncodeToString(messageByte.Bytes())

		// Отправляем в socket
		fmt.Fprintf(conn, messageToSend+"\n")

		bufio.NewReader(conn).ReadString('\n')
	}
}
