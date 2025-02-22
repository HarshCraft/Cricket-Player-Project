from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from pymongo import MongoClient
from bson.objectid import ObjectId
import bcrypt

app = Flask(__name__)
app.secret_key = 'your_secret_key'  


client = MongoClient("mongodb://localhost:27017/")
db = client.cricket_db
players_collection = db.players
users_collection = db.users  
ratings_collection = db.ratings  
performance_collection = db.performances  


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login' 

class User(UserMixin):
    pass

@login_manager.user_loader
def load_user(user_id):
    user = users_collection.find_one({"_id": ObjectId(user_id)})
    if user:
        user_obj = User()
        user_obj.id = str(user['_id'])
        return user_obj
    return None

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        users_collection.insert_one({"username": username, "password": hashed_pw})
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = users_collection.find_one({"username": username})
        if user and bcrypt.checkpw(password.encode('utf-8'), user['password']):
            user_obj = User()
            user_obj.id = str(user['_id'])
            login_user(user_obj)
            return redirect(url_for('index'))  
        flash('Invalid credentials')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
def home():
    return redirect(url_for('login'))


@app.route('/index')
@login_required
def index():
    return render_template('index.html')

@app.route('/player/<player_id>', methods=['GET', 'POST'])
@login_required
def player_details(player_id):
  
    player = players_collection.find_one({'_id': ObjectId(player_id)})
    
   
    reviews = list(ratings_collection.find({'player_id': player_id}))
    
    if request.method == 'POST':
       
        review = {
            'review': request.form['review'],
            'rating': int(request.form['rating']),
            'user_id': current_user.id,
            'player_id': player_id  
        }
        ratings_collection.insert_one(review)
        return redirect(url_for('player_details', player_id=player_id))
    
    return render_template('player_details.html', player=player, reviews=reviews)

@app.route('/delete_review/<player_id>/<review_id>', methods=['POST'])
@login_required
def delete_review(player_id, review_id):
    review = ratings_collection.find_one({"_id": ObjectId(review_id)})
    if review and review['user_id'] == current_user.id:
        ratings_collection.delete_one({"_id": ObjectId(review_id)})
    return redirect(url_for('player_details', player_id=player_id))

@app.route('/add', methods=['GET', 'POST'])
@login_required
def add_player():
    if request.method == 'POST':
        player = {
            "name": request.form['name'],
            "jersey_number": int(request.form['jersey_number']),
            "matches_played": int(request.form['matches_played']),
            "wickets_taken": int(request.form['wickets_taken']),
            "runs_scored": int(request.form['runs_scored']),
            "special_skill": request.form['special_skill'],
        }
        players_collection.insert_one(player)
        return redirect(url_for('player_list'))
    return render_template('add_player.html')

@app.route('/players')
@login_required
def player_list():
    players = players_collection.find()
    return render_template('player_list.html', players=players)

@app.route('/update/<player_id>', methods=['GET', 'POST'])
@login_required
def update_player(player_id):
    player = players_collection.find_one({"_id": ObjectId(player_id)})
    if request.method == 'POST':
        updated_player = {
            "name": request.form['name'],
            "jersey_number": int(request.form['jersey_number']),
            "matches_played": int(request.form['matches_played']),
            "wickets_taken": int(request.form['wickets_taken']),
            "runs_scored": int(request.form['runs_scored']),
            "special_skill": request.form['special_skill'],
        }
        players_collection.update_one({"_id": ObjectId(player_id)}, {"$set": updated_player})
        return redirect(url_for('player_list'))
    return render_template('update_player.html', player=player)

@app.route('/delete/<player_id>')
@login_required
def delete_player(player_id):
    players_collection.delete_one({"_id": ObjectId(player_id)})
    return redirect(url_for('player_list'))

@app.route('/search_player', methods=['GET'])
@login_required
def search_player():
    jersey_number = request.args.get('jersey_number')
    player = players_collection.find_one({'jersey_number': int(jersey_number)})
    if player:
        return redirect(url_for('player_details', player_id=player['_id']))
    else:
        return render_template('player_not_found.html', jersey_number=jersey_number)

@app.route('/more_info/<player_id>')
@login_required
def more_info(player_id):
    performances = performance_collection.find({"player_id": ObjectId(player_id)})
    player = players_collection.find_one({"_id": ObjectId(player_id)})
    return render_template('more_info.html', player=player, performances=performances)

@app.route('/add_performance/<player_id>', methods=['GET', 'POST'])
@login_required
def add_performance(player_id):
    if request.method == 'POST':
        performance = {
            "player_id": ObjectId(player_id),
            "year": int(request.form['year']),
            "matches_played": int(request.form['matches_played']),
            "runs_scored": int(request.form['runs_scored']),
            "wickets_taken": int(request.form['wickets_taken']),
        }
        performance_collection.insert_one(performance)
        return redirect(url_for('more_info', player_id=player_id))
    return render_template('add_performance.html', player_id=player_id)

@app.route('/delete_performance/<player_id>/<year>')
@login_required
def delete_performance(player_id, year):
    performance_collection.delete_one({"player_id": ObjectId(player_id), "year": int(year)})
    return redirect(url_for('more_info', player_id=player_id))

if __name__ == '__main__':
    app.run(debug=True)
