# Serenify

## Inspiration

Mental health is a crucial yet often neglected aspect of student life. With the pressures of academics, deadlines, and personal challenges, students often face mental health issues that go unnoticed. To address this, we created **Serenify**, a platform that proactively supports students' mental well-being. Our goal is to provide consistent mental health support seamlessly integrated into students' daily routines.

## What it does

**Serenify** is a comprehensive platform designed to assess, track, and improve students' mental health in a simple, engaging manner:

### Features:
1. **Emotional Analysis**: 
   - Students upload a photo, and Serenify uses Computer Vision and DeepFace to assess their emotional state (e.g., happy, neutral, or unhappy).
   
2. **Chatbot Support**: 
   - Powered by the **Gemini API**, Serenify’s chatbot engages in meaningful conversations with students, offering personalized interactions and support.
   
3. **Daily Tips**: 
   - At the end of each interaction, students receive five actionable tips tailored to their emotional state, helping them improve their mood or stay motivated.
   
4. **Rewards System**: 
   - Students earn points for daily check-ins, which they can redeem for perks such as food court discounts, encouraging consistent engagement.
   
5. **Proactive Escalation**: 
   - For students displaying consistent signs of distress, Serenify can escalate their data to campus mental health teams or peer mentors for timely intervention.

## How we built it

### Languages and Frameworks:
- **Python**, **Flask**, **HTML**, **CSS**, and **JavaScript**

### APIs/ Libraries:
- **Gemini API** for chatbot functionality
- **DeepFace** for emotional photo analysis

### Authentication:
- **OAuth with Google** for secure login

### Database:
- **SQL** for storing user data, streaks, and emotional history

### Key Features:
- **Emotion detection** integrated with DeepFace and Computer Vision tools
- **Chatbot** developed using the Gemini API
- **Points and streak system** to encourage daily engagement

## Challenges we ran into

1. **Photo Analysis Integration**: 
   - Ensuring accurate emotional detection using Computer Vision and DeepFace while maintaining system performance was challenging.

2. **Seamless User Experience**: 
   - Striking the right balance between technical features and an intuitive, engaging design.

3. **Privacy Concerns**: 
   - Addressing the ethical and secure handling of sensitive user data was a top priority.

4. **Scalability**: 
   - Designing the system with scalability in mind, focusing on a functional MVP while conceptualizing future features like report generation.

## Accomplishments that we're proud of

- Successfully integrating **DeepFace** for emotional analysis.
- Creating a chatbot using **Gemini API** that provides personalized, meaningful conversations.
- Developing a **rewards system** that encourages regular mental health check-ins.
- Building a **fully functional website** accessible across all devices.

## What we learned

- Integrating AI tools such as **DeepFace** and **Gemini API** into a functional web application.
- The importance of privacy and ethical considerations when creating mental health solutions.
- Managing time effectively and collaborating under tight deadlines.

## What's next for Serenify

1. **Scalable Features**: 
   - Forwarding user reports to the on-campus Health and Wellness department for deeper insights and interventions.

2. **Expanded Rewards System**: 
   - Partnering with more campus services and local businesses to offer enhanced rewards.

3. **Campus-wide Integration**: 
   - Collaborating with Sheridan to integrate Serenify into SLATE as a course or resource.

4. **Advanced Analytics**: 
   - Enhancing emotional detection with real-time feedback and detailed insights.

5. **Awareness Campaigns**: 
   - Partnering with student organizations to promote the platform and normalize proactive mental health care.

## Built With

- **ComputerVision**
- **CSS**
- **DeepFace**
- **Flask**
- **Gemini API**
- **Google Authentication (OAuth)**
- **HTML**
- **JavaScript**
- **Python**
- **SQL**
