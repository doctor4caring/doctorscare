importScripts('https://www.gstatic.com/firebasejs/9.0.0/firebase-app-compat.js');
importScripts('https://www.gstatic.com/firebasejs/9.0.0/firebase-messaging-compat.js');

 //the Firebase config object 
 const firebaseConfig = {
    apiKey: "AIzaSyAgkltLnZ2w9R9-43jJb8zyCSUQ6wyVLbg",
    authDomain: "test-famdoc.firebaseapp.com",
    projectId: "test-famdoc",
    storageBucket: "test-famdoc.appspot.com",
    messagingSenderId: "549887321649",
    appId: "1:549887321649:web:e7631b0bfb6d51b9ccd710",
    measurementId: "G-X6QME8ZHTK"
};

firebase.initializeApp(firebaseConfig);
const messaging = firebase.messaging();

messaging.onBackgroundMessage(function(payload) {
  // console.log('Received background message ', payload);
  const notificationTitle = payload.notification.title;
  const notificationOptions = {
    body: payload.notification.body,
  };

  self.registration.showNotification(notificationTitle,
    notificationOptions);
});