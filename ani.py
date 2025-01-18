import cv2

# Open the camera
camera = cv2.VideoCapture(0)

# Check if the camera opened successfully
if not camera.isOpened():
    print("Error: Could not access the camera.")
    exit()

while True:
    success, frame = camera.read()
    if not success:
        print("Error: Failed to capture image.")
        break

    # Display the captured frame
    cv2.imshow("Camera Feed", frame)

    # Exit the loop if 'q' is pressed
    if cv2.waitKey(1) & 0xFF == ord('q'):
        break

camera.release()
cv2.destroyAllWindows()
