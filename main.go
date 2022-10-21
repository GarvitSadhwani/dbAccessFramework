package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"text/template"

	//"time"

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
	StaticHandler(w, "templates/home.gohtml")
}

func signupHandler(w http.ResponseWriter, r *http.Request) {
	StaticHandler(w, "templates/signup.gohtml")
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
	router.Get("/home", controllers.landingHandler)
	http.Redirect(w, r, "/home"+title, http.StatusSeeOther)
}

func main() {
	router = chi.NewRouter()
	db, err := sql.Open("pgx", "host=localhost port=5432 user=frameworkdb password=frameworkdb dbname=dbacsfrm sslmode=disable")
	if err != nil {
		fmt.Println("error connecting to database")
	}
	err = db.Ping()
	if err != nil {
		fmt.Println("cant communicate with database")
	}
	defer db.Close()
	router.Get("/home", homeHandler)
	router.Get("/landing", controllers.landingHandler)
	router.Get("/signup", signupHandler)
	router.Post("/newuser", addUser)
	router.Post("/loginuser", controllers.authUser)
	fmt.Println("Starting server at port: 8080")
	http.ListenAndServe(":8080", router)

}
