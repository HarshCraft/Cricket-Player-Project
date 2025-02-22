# Cricket_Player_Management
This project is a web application that allows users to manage cricket players' statistics using a MongoDB database. The application is built using Flask, and it provides functionalities to add, update, delete, search using jersey number, and list cricket players and their statistics.

# Cricket Player Management System

We recently developed a comprehensive database project for managing cricket players using MongoDB, with a sleek and intuitive frontend built with HTML and CSS. Here's a breakdown of what this project entails:

## Frontend Development
- *Technologies Used*:HTML, CSS

- *Features*:
  - Designed an interactive and user-friendly web page.
  - The interface allows users to effortlessly add, delete, update, and search for cricket players by their jersey number.

## Backend Integration
- *Technologies Used*: Python, MongoDB

- *Features*:
  - Seamlessly connect the frontend with the MongoDB database, ensuring smooth data operations and real-time updates.

## Key Features
- *Add Players*: Effortlessly add new players to the database.
- *Delete Players*: Remove players from the list with a single click.
- *Update Player Details*: Modify player information quickly and efficiently.
- *Search Functionality*: Instantly find players by their jersey number, ensuring easy access to specific data.

## Project Journey
This project has been a fantastic journey, combining our skills in web development and database management. We are thrilled to see the potential applications and further improvements that can be made.

### Technologies Used
- MongoDB
- Python
- HTML
- CSS

### How to Run

## Software Requirements

1. **Visual Studio Code**
2. **MongoDB and MongoDB Compass**
3. **Python IDE** (such as PyCharm, VS Code, etc.)
4. **Python Packages**
   - Flask
   - Flask-PyMongo
   - dnspython

You can install the required Python packages using the following commands:

```bash
pip install Flask Flask-PyMongo dnspython
```

## Setup Instructions

### Step 1: Install MongoDB
If MongoDB is not already installed on your system, download and install it from the [official MongoDB website](https://www.mongodb.com/try/download/community).

### Step 2: Start MongoDB
Start the MongoDB server by running the following command in your terminal or command prompt:

```bash
mongod
```

Make sure the MongoDB server is running before proceeding.

### Step 3: Create the Database and Collection

#### Using MongoDB Shell

1. Open a new terminal or command prompt.
2. Start the MongoDB shell by running the following command:

   ```bash
   mongo
   ```

3. Create a database named `cricket_db`:

   ```bash
   use cricket_db
   ```

4. Create a collection named `players`:

   ```bash
   db.createCollection("players")
   ```

5. Verify the creation of the database and collection:

   ```bash
   show dbs
   use cricket_db
   show collections
   ```

#### Step 4: Insert Sample Data

Optionally, you can insert some sample data into the `players` collection to get started:

```bash
db.players.insertMany([
    {
        "name": "Player One",
        "jersey_number": 10,
        "matches_played": 50,
        "wickets_taken": 100,
        "runs_scored": 2000,
        "special_skill": "Batsman"
    },
    {
        "name": "Player Two",
        "jersey_number": 12,
        "matches_played": 40,
        "wickets_taken": 80,
        "runs_scored": 1500,
        "special_skill": "All-rounder"
    }
])
```

6. Verify that the data has been inserted correctly:

   ```bash
   db.players.find().pretty()
   ```

### Using MongoDB Compass

1. Download and install MongoDB Compass from the [official MongoDB Compass website](https://www.mongodb.com/products/compass).

2. Open MongoDB Compass and connect to your local MongoDB server (usually `mongodb://localhost:27017`).

3. Create Database and Collection:
   - Click on the "Create Database" button.
   - Enter `cricket_db` as the database name.
   - Enter `players` as the collection name.
   - Click "Create Database."

4. Insert Sample Data:
   - Navigate to the `players` collection.
   - Click on the "Insert Document" button.
   - Insert the sample documents as shown above.

## Running the Application

1. Save your Flask application code in a file named `app.py`.

2. Run the Flask application:

   ```bash
   python app.py
   ```

3. Open your web browser and navigate to [http://127.0.0.1:5000/](http://127.0.0.1:5000/) to see the application in action.

You should be able to add, update, delete, search using jersey number, and list cricket players and their statistics using the MongoDB database.

## Conclusion

This README provides detailed instructions on setting up the development environment, creating the MongoDB database and collection, inserting sample data, and running the Flask application. Follow these steps to get your Cricket Players Management application up and running.
"# Cricket-Player-Management-Project" 
