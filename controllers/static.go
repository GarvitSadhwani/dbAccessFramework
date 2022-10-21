package controllers

import (
	"database/sql"
	"fmt"
	"go_prac/houseware/dbAccessFramework/templates"
	"go_prac/houseware/dbAccessFramework/views"
	"net/http"
	"text/template"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	chi "github.com/go-chi/chi/v5"
	_ "github.com/jackc/pgx/v4/stdlib"
	"golang.org/x/crypto/bcrypt"
)

var router *chi.Mux
var jwtKey = []byte("my_secret_key")

type Credentials struct {
	Username string `json:"email"`
	Password string `json:"password"`
}

type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

func StaticHandler(w http.ResponseWriter, file string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tpl, err := template.ParseFiles(file)
	if err != nil {
		fmt.Printf("error parsing")
	}
	err = tpl.Execute(w, nil)
	if err != nil {
		fmt.Printf("error executing")
	}
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	tpl, _ := views.ParseFS(templates.FS, "home.gohtml")
	tpl.Execute(w, nil)
	//StaticHandler(w, "templates/home.gohtml")
}

func signupHandler(w http.ResponseWriter, r *http.Request) {
	tpl, _ := views.ParseFS(templates.FS, "signup.gohtml")
	tpl.Execute(w, nil)
}

func addUser(w http.ResponseWriter, r *http.Request) {
	db, err := sql.Open("pgx", "host=localhost port=5432 user=frameworkdb password=frameworkdb dbname=dbacsfrm sslmode=disable")
	if err != nil {
		fmt.Println("error connecting to database")
	}
	err = db.Ping()
	if err != nil {
		fmt.Println("cant communicate with database")
	}

	res, err := db.Query("select count(*) from users")

	if err != nil {
		fmt.Println("error running query")
	}
	defer res.Close()
	var count int
	for res.Next() {
		err = res.Scan(&count)
		if err != nil {
			fmt.Println("error retrieving data from row")
		}
	}
	count++
	enstr, err := bcrypt.GenerateFromPassword([]byte(r.FormValue("password")), 14)
	if err != nil {
		fmt.Printf("error computing password hash")
	}
	hashstr := string(enstr)
	_, err = db.Exec(`insert into users values($1,$2,$3,$4,$5);`, count, r.FormValue("first_name"), r.FormValue("last_name"), r.FormValue("email"), hashstr)
	if err != nil {
		fmt.Println("error entering into database")
	}

	defer db.Close()
	title := r.URL.Path[len("/adduser"):]
	router.Get("/home", landingHandler)
	http.Redirect(w, r, "/home"+title, http.StatusSeeOther)
}

func landingHandler(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("token")
	if err != nil {
		if err == http.ErrNoCookie {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	tknStr := c.Value
	claims := &Claims{}

	tkn, err := jwt.ParseWithClaims(tknStr, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if !tkn.Valid {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	tpl, _ := views.ParseFS(templates.FS, "landing.gohtml")
	tpl.Execute(w, claims.Username)
}

func authUser(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("in func")
	var creds Credentials

	db, err := sql.Open("pgx", "host=localhost port=5432 user=frameworkdb password=frameworkdb dbname=dbacsfrm sslmode=disable")
	if err != nil {
		fmt.Println("error connecting to database")
	}
	err = db.Ping()
	if err != nil {
		fmt.Println("cant communicate with database")
	}

	res, err := db.Query("select * from users where email=$1", r.FormValue("email"))

	if err != nil {
		fmt.Println("error running query")
	}
	defer res.Close()
	var count int
	var f_name string
	var l_name string
	var em string
	var pass string
	for res.Next() {
		err = res.Scan(&count, &f_name, &l_name, &em, &pass)
		if err != nil {
			fmt.Println("error retrieving data from row")
		}
	}
	defer db.Close()
	title := r.URL.Path[len("/loginuser"):]
	err = bcrypt.CompareHashAndPassword([]byte([]byte(pass)), []byte(r.FormValue("password")))
	if err == nil {
		fmt.Printf("pass verified")
		creds.Username = r.FormValue("email")
		expirationTime := time.Now().Add(5 * time.Minute)
		claims := &Claims{
			Username: creds.Username,
			StandardClaims: jwt.StandardClaims{
				ExpiresAt: expirationTime.Unix(),
			},
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err := token.SignedString(jwtKey)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:    "token",
			Value:   tokenString,
			Expires: expirationTime,
		})
		fmt.Printf("redirecting")
		router.Get("/landing", landingHandler)
		http.Redirect(w, r, "/landing"+title, http.StatusSeeOther)
	} else {
		fmt.Print("wrong pass")
		router.Get("/home", homeHandler)
		http.Redirect(w, r, "/home"+title, http.StatusSeeOther)
	}

}
