package main

import (
	"database/sql"
	"fmt"
	"go_prac/houseware/dbAccessFramework/controllers"
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

//Funciton to add a new User to the database
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

//Function to add a new Database for a User
func newdb(w http.ResponseWriter, r *http.Request) {
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
	db, err := sql.Open("pgx", "host=localhost port=5432 user=frameworkdb password=frameworkdb dbname=dbacsfrm sslmode=disable")
	if err != nil {
		fmt.Println("error connecting to database")
	}
	err = db.Ping()
	if err != nil {
		fmt.Println("cant communicate with database")
	}

	enstr, err := bcrypt.GenerateFromPassword([]byte(r.FormValue("password")), 14)
	if err != nil {
		fmt.Printf("error computing password hash")
	}
	hashstr := string(enstr)
	_, err = db.Exec(`insert into databases values($1,$2,$3,$4,$5);`, claims.Username, r.FormValue("dbhost"), r.FormValue("dbname"), hashstr, r.FormValue("password"))
	if err != nil {
		fmt.Println("error entering into database")
	}

	defer db.Close()
	title := r.URL.Path[len("/adddb"):]
	router.Get("/landing", landingHandler)
	http.Redirect(w, r, "/landing"+title, http.StatusSeeOther)
}

//Function to get the User to their homepage
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
	tpl, _ := template.ParseFiles("templates/landing.gohtml")
	tpl.Execute(w, claims.Username)
}

//Function to authenticate and provide User access to their database
func authdb(w http.ResponseWriter, r *http.Request) {
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

	db, err := sql.Open("pgx", "host=localhost port=5432 user=frameworkdb password=frameworkdb dbname=dbacsfrm sslmode=disable")
	if err != nil {
		fmt.Println("error connecting to database")
	}
	err = db.Ping()
	if err != nil {
		fmt.Println("cant communicate with database")
	}

	res, err := db.Query("select * from databases where email=$1", claims.Username)

	if err != nil {
		fmt.Println("error running query")
	}
	defer res.Close()
	var email string
	var db_host string
	var db_name string
	var port string
	var pass string
	for res.Next() {
		err = res.Scan(&email, &db_host, &db_name, &pass, &port)
		if err != nil {
			fmt.Println("error retrieving data from row")
		}
	}
	defer db.Close()
	title := r.URL.Path[len("/fetchdb"):]
	err = bcrypt.CompareHashAndPassword([]byte([]byte(pass)), []byte(r.FormValue("password")))

	if err == nil {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, "Connected to: ", db_name)
		fmt.Fprint(w, "\n \n <a href=\"/showtables\">Click to view list of tables present here</a>")
		fmt.Fprint(w, "\n \n <a href=\"/landing\">Click to go back</a>")
	} else {
		fmt.Print("wrong pass")
		router.Get("/landing", landingHandler)
		http.Redirect(w, r, "/landing"+title, http.StatusSeeOther)
	}
}

//Function to authenticate User Credentials and post it in the Cookie for user
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
		expirationTime := time.Now().Add(24 * time.Hour) //Adding an expiry of 24 hours
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
		tpl, _ := views.ParseFS(templates.FS, "home.gohtml")
		router.Get("/home", controllers.StaticHandler(tpl))
		http.Redirect(w, r, "/home"+title, http.StatusSeeOther)
	}

}

//Function that can retrieve the list of Tables from Users' Database host
func tableViewer(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, "!List of tables retrieved from database host!")
	fmt.Fprint(w, "\n \n <a href=\"/landing\">Click to go to homepage/a>")
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
	tpl, _ := views.ParseFS(templates.FS, "home.gohtml")
	router.Get("/home", controllers.StaticHandler(tpl))
	router.Get("/landing", landingHandler)
	tpl, _ = views.ParseFS(templates.FS, "signup.gohtml")
	router.Get("/signup", controllers.StaticHandler(tpl))
	router.Get("/showtables", tableViewer)
	router.Post("/newuser", addUser)
	router.Post("/loginuser", authUser)
	router.Post("/fetchdb", authdb)
	router.Post("/adddb", newdb)
	fmt.Println("Starting server at port: 8080")
	http.ListenAndServe(":8080", router)

}
