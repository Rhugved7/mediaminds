from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import requests
import os
import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from wordcloud import WordCloud
import re
from textblob import TextBlob
from collections import Counter
import json

app = Flask(__name__)

# Configuration
UPLOAD_FOLDER = 'static/uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.secret_key = 'your-secret-key-here'  

# Twitter API Configuration
bearer_token = "AAAAAAAAAAAAAAAAAAAAAH890gEAAAAAAZa%2FlxfXKFY6ZpFAyKo6x78RMdk%3DAyyXLefe7vhid0WKOTOF0J0ceAsmZ5Ykkqif6udIBpDCmHJuiX"  # Replace with bearer token

# Database Initialization
def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                 username TEXT UNIQUE NOT NULL,
                 password TEXT NOT NULL)''')
    conn.commit()
    conn.close()

init_db()

# Helper Functions
def create_headers():
    return {"Authorization": f"Bearer {bearer_token}", "Content-Type": "application/json"}

def fetch_tweets(query, max_results=100):
    url = f"https://api.twitter.com/2/tweets/search/recent?query={query}&max_results={max_results}&tweet.fields=created_at,public_metrics,entities"
    headers = create_headers()
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    return None

def clean_text(text):
    text = re.sub(r'@[A-Za-z0-9_]+', '', text)
    text = re.sub(r'#[A-Za-z0-9_]+', '', text)
    text = re.sub(r'https?://\S+', '', text)
    text = re.sub(r'[^a-zA-Z0-9 ]', '', text)
    return text.lower()

# Authentication Routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = c.fetchone()
        conn.close()
        
        if user and check_password_hash(user[2], password):
            session['user_id'] = user[0]
            session['username'] = user[1]
            flash('Logged in successfully!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password', 'danger')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return redirect(url_for('register'))
        
        if len(password) < 8:
            flash('Password must be at least 8 characters', 'danger')
            return redirect(url_for('register'))
        
        hashed_password = generate_password_hash(password)
        
        try:
            conn = sqlite3.connect('users.db')
            c = conn.cursor()
            c.execute('INSERT INTO users (username, password) VALUES (?, ?)', 
                     (username, hashed_password))
            conn.commit()
            conn.close()
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists', 'danger')
    
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

# Main Application Routes
@app.route('/')
def index():
    if 'user_id' not in session:
        return render_template('index.html')
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    if 'user_id' not in session:
        flash('Please login to access this feature', 'danger')
        return redirect(url_for('login'))

    query = request.form['query']
    tweet_data = fetch_tweets(query)

    sentiment_counts = {"Positive": 0, "Negative": 0, "Neutral": 0}
    hashtag_counts, mention_counts = {}, {}
    most_liked_tweet, most_retweeted_tweet, wordcloud_path = None, None, None
    sentiment_chart_path = hashtag_chart_path = mention_chart_path = None
    tweet_list = []

    if tweet_data and "data" in tweet_data:
        all_text, hashtags, mentions = [], [], []

        for tweet in tweet_data["data"]:
            text = clean_text(tweet["text"])
            all_text.append(text)
            sentiment_score = TextBlob(text).sentiment.polarity
            sentiment = "Positive" if sentiment_score > 0 else "Negative" if sentiment_score < 0 else "Neutral"
            sentiment_counts[sentiment] += 1
            
            if "entities" in tweet:
                hashtags += [h['tag'] for h in tweet["entities"].get("hashtags", [])]
                mentions += [m['username'] for m in tweet["entities"].get("mentions", [])]

            tweet_info = {
                "Tweet": tweet["text"],
                "Sentiment": sentiment,
                "Likes": tweet["public_metrics"]["like_count"],
                "Retweets": tweet["public_metrics"]["retweet_count"]
            }
            tweet_list.append(tweet_info)

        # Generate Word Cloud
        wordcloud = WordCloud(width=800, height=400, background_color='white').generate(" ".join(all_text))
        wordcloud_path = os.path.join(app.config['UPLOAD_FOLDER'], 'wordcloud.png')
        wordcloud.to_file(wordcloud_path)

        # Generate Sentiment Chart
        plt.figure(figsize=(6,4))
        plt.bar(sentiment_counts.keys(), sentiment_counts.values(), color=['green', 'red', 'gray'])
        plt.title("Sentiment Distribution")
        plt.xlabel("Sentiment")
        plt.ylabel("Tweet Count")
        sentiment_chart_path = os.path.join(app.config['UPLOAD_FOLDER'], 'sentiment_chart.png')
        plt.savefig(sentiment_chart_path)
        plt.close()

        # Generate Hashtag Chart
        if hashtags:
            hashtag_counts = dict(Counter(hashtags).most_common(10))
            plt.figure(figsize=(6,4))
            plt.bar(hashtag_counts.keys(), hashtag_counts.values(), color='skyblue')
            plt.title("Top Hashtags")
            plt.xlabel("Hashtags")
            plt.ylabel("Frequency")
            plt.xticks(rotation=45, ha='right')
            plt.tight_layout()
            hashtag_chart_path = os.path.join(app.config['UPLOAD_FOLDER'], 'hashtag_chart.png')
            plt.savefig(hashtag_chart_path)
            plt.close()

        # Generate Mention Chart
        if mentions:
            mention_counts = dict(Counter(mentions).most_common(10))
            plt.figure(figsize=(6,4))
            plt.bar(mention_counts.keys(), mention_counts.values(), color='orange')
            plt.title("Top Mentions")
            plt.xlabel("Mentions")
            plt.ylabel("Frequency")
            plt.xticks(rotation=45, ha='right')
            plt.tight_layout()
            mention_chart_path = os.path.join(app.config['UPLOAD_FOLDER'], 'mention_chart.png')
            plt.savefig(mention_chart_path)
            plt.close()

        # Get most popular tweets
        if tweet_list:
            df = pd.DataFrame(tweet_list)
            most_liked_tweet = df.loc[df['Likes'].idxmax()].to_dict()
            most_retweeted_tweet = df.loc[df['Retweets'].idxmax()].to_dict()

    return render_template('results.html',
                         sentiment_counts=sentiment_counts,
                         wordcloud_path=wordcloud_path,
                         sentiment_chart_path=sentiment_chart_path,
                         hashtag_chart_path=hashtag_chart_path,
                         mention_chart_path=mention_chart_path,
                         hashtag_counts=hashtag_counts,
                         mention_counts=mention_counts,
                         most_liked_tweet=most_liked_tweet,
                         most_retweeted_tweet=most_retweeted_tweet,
                         tweets=tweet_list)

@app.route('/upload', methods=['POST'])
def upload():
    if 'user_id' not in session:
        flash('Please login to access this feature', 'danger')
        return redirect(url_for('login'))

    if 'file' not in request.files:
        flash('No file uploaded', 'danger')
        return redirect(url_for('index'))

    file = request.files['file']
    if file.filename == '':
        flash('No selected file', 'danger')
        return redirect(url_for('index'))

    if file:
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(filepath)

        try:
            df = pd.read_csv(filepath)
            df.columns = df.columns.str.lower()
            valid_text_columns = ['tweet', 'text', 'content', 'message']
            text_column = next((col for col in df.columns if col in valid_text_columns), None)
            
            if text_column is None:
                flash('No valid text column found in the CSV', 'danger')
                return redirect(url_for('index'))

            # Perform analysis
            df['Sentiment'] = df[text_column].apply(
                lambda x: "Positive" if TextBlob(str(x)).sentiment.polarity > 0 
                else "Negative" if TextBlob(str(x)).sentiment.polarity < 0 
                else "Neutral"
            )
            
            sentiment_counts = df['Sentiment'].value_counts().to_dict()
            hashtags = [tag for text in df[text_column].dropna() for tag in re.findall(r'#\w+', str(text))]
            hashtag_counts = Counter(hashtags).most_common(10)

            # Generate Word Cloud
            text_data = " ".join(df[text_column].dropna().astype(str))
            wordcloud = WordCloud(width=800, height=400, background_color='white').generate(text_data)
            wordcloud_path = os.path.join(app.config['UPLOAD_FOLDER'], 'wordcloud.png')
            wordcloud.to_file(wordcloud_path)

            # Generate Sentiment Chart
            plt.figure(figsize=(6,4))
            plt.bar(sentiment_counts.keys(), sentiment_counts.values(), color=['green', 'red', 'gray'])
            plt.title("Sentiment Distribution")
            plt.xlabel("Sentiment")
            plt.ylabel("Tweet Count")
            sentiment_chart_path = os.path.join(app.config['UPLOAD_FOLDER'], 'sentiment_chart.png')
            plt.savefig(sentiment_chart_path)
            plt.close()

            # Generate Hashtag Chart
            if hashtag_counts:
                plt.figure(figsize=(6,4))
                hashtags, values = zip(*hashtag_counts)
                plt.bar(hashtags, values, color='skyblue')
                plt.title("Top Hashtags")
                plt.xlabel("Hashtags")
                plt.ylabel("Frequency")
                plt.xticks(rotation=45, ha='right')
                plt.tight_layout()
                hashtag_chart_path = os.path.join(app.config['UPLOAD_FOLDER'], 'hashtag_chart.png')
                plt.savefig(hashtag_chart_path)
                plt.close()

            return render_template('results.html',
                                 sentiment_counts=sentiment_counts,
                                 wordcloud_path=wordcloud_path,
                                 sentiment_chart_path=sentiment_chart_path,
                                 hashtag_chart_path=hashtag_chart_path,
                                 tweets=df.to_dict(orient='records'))

        except Exception as e:
            flash(f'Error processing file: {str(e)}', 'danger')
            return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)