from flask import Flask, render_template, Response, request, redirect, flash, url_for, session
import cv2
from dotenv import load_dotenv
import os
import requests
from deepface import DeepFace
from pprint import pprint
from flask_socketio import SocketIO, emit


GPT_API_KEY=os.getenv('')

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Required for flash messages

# Initialize the webcam
camera = cv2.VideoCapture(0)

# Load a pre-trained face detection model
face_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_frontalface_default.xml')

# Threshold for minimum face size to ensure the face is close enough
MIN_FACE_SIZE = 100

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/video_feed')
def video_feed():
    def generate_frames():
        while True:
            success, frame = camera.read()
            if not success:
                break
            else:
                # Resize the frame to make it smaller
                frame = cv2.resize(frame, (300, 300))

                # Convert to grayscale for face detection
                gray_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)

                # Detect faces
                faces = face_cascade.detectMultiScale(gray_frame, scaleFactor=1.1, minNeighbors=5, minSize=(30,30))

                # Encode frame to JPEG format
                ret, buffer = cv2.imencode('.jpg', frame)
                frame = buffer.tobytes()
                yield (b'--frame\r\n'
                       b'Content-Type: image/jpeg\r\n\r\n' + frame + b'\r\n')

    return Response(generate_frames(), mimetype='multipart/x-mixed-replace; boundary=frame')

@app.route('/shoot', methods=['GET','POST'])
def shoot():
    return render_template('index.html')

@app.route('/capture', methods=['POST'])
def capture():
    success, frame = camera.read()
    if not success:
        print("Error: Failed to capture image.")
        flash('Failed to capture image.', 'error')
        return redirect(url_for('shoot'))

    if success:
        # Convert to grayscale for face detection
        gray_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)

        # Detect faces
        faces = face_cascade.detectMultiScale(gray_frame, scaleFactor=1.1, minNeighbors=5, minSize=(60, 60))

        if len(faces) == 0:
            flash('No face detected. Please move closer to the camera.', 'error')
            return redirect(url_for('shoot'))

        for (x, y, w, h) in faces:
            if w >= MIN_FACE_SIZE and h >= MIN_FACE_SIZE:
                # Crop the face region
                face_frame = frame[y:y + h, x:x + w]

                # Resize and save the face region
                face_frame = cv2.resize(face_frame, (400, 400))
                save_path = os.path.join('static', 'captured_image.jpg')
                cv2.imwrite(save_path, face_frame)

                # Analyze the captured image for emotions
                try:
                    analysis = DeepFace.analyze(save_path, actions=['emotion'])

                    # Extract the emotions and their confidence scores
                    emotion_scores = analysis[0]['emotion']

                    # Find the emotion with the highest score
                    dominant_emotion = max(emotion_scores, key=emotion_scores.get)
                    dem_em = "happy" if dominant_emotion == 'happy' else "not happy"

                    # Save the image and emotion in the session
                    session['captured_image'] = save_path
                    session['dominant_emotion'] = dem_em

                    flash('Image captured and analyzed successfully!', 'success')
                    return redirect(url_for('captured'))

                except Exception as e:
                    flash(f'Failed to analyze image: Reposition Yourself', 'error')
                    return redirect(url_for('shoot'))

        flash("Face detected but not close enough. Please move closer.", 'warning')
        return redirect(url_for('shoot'))

    flash('Failed to capture image.', 'error')
    return redirect(url_for('shoot'))

@app.route('/chatbot', methods=['GET','POST'])
def chatbot():
    return render_template('chatbot.html')

@app.route('/captured')
def captured():
    captured_image = session.get('captured_image', None)
    dominant_emotion = session.get('dominant_emotion', None)
    return render_template('captured.html', captured_image=captured_image, dominant_emotion=dominant_emotion)

@app.route('/retry')
def retry():
    # Remove the captured image and emotion from the session to allow retry
    session.pop('captured_image', None)
    session.pop('dominant_emotion', None)
    flash('You can now retake your image.', 'info')
    return redirect(url_for('shoot'))



if __name__ == '__main__':
    try:
        app.run(debug=True)
    except Exception as e:
        print(f"Error occurred: {str(e)}")
