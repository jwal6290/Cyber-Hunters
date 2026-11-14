

// Import Firebase
import { initializeApp } from "https://www.gstatic.com/firebasejs/13.3.0/firebase-app.js";

import {
    getFirestore,
    doc,
    setDoc,
    serverTimestamp,
    collection,
    getDocs,
    deleteDoc
} from "https://www.gstatic.com/firebasejs/13.3.0/firebase-firestore.js";

import {
    getAuth,
    signInAnonymously,
    onAuthStateChanged
} from "https://www.gstatic.com/firebasejs/13.3.0/firebase-auth.js";

import {
    getFirestore,
    doc,
    setDoc,
    serverTimestamp,
    collection,
    getDocs
} from "https://www.gstatic.com/firebasejs/13.3.0/firebase-firestore.js";

// Your web app's Firebase configuration
const firebaseConfig = {
    apiKey: "AIzaSyAhBHBlrKJwKzMFriEhAeCcxTFiNxJfOso",
    authDomain: "scamshieldai-78d0e.firebaseapp.com",
    projectId: "scamshieldai-78d0e",
    storageBucket: "scamshieldai-78d0e.firebasestorage.app",
    messagingSenderId: "297812250276",
    appId: "1:297812250276:web:2d7bce1f8c83501432a031",
    measurementId: "G-MKE7P07KT3"
};

// Initialize Firebase
const app = initializeApp(firebaseConfig);

// Connect to Firestore
const db = getFirestore(app);

// Initialize Authentication
const auth = getAuth(app);

// Wait for an existing user or create an anonymous user
const authReady = new Promise((resolve, reject) => {
    const unsubscribe = onAuthStateChanged(auth, (user) => {
        unsubscribe();

        if (user) {
            console.log("Existing user found:", user.uid);
            resolve(user);
        } else {
            signInAnonymously(auth)
                .then((result) => {
                    console.log("Anonymous user created:", result.user.uid);
                    resolve(result.user);
                })
                .catch((error) => {
                    console.error("Anonymous sign-in failed:", error);
                    reject(error);
                });
        }
    }, reject);
});

// Make Firebase available to other JavaScript files
export { app, db, auth, authReady };

console.log("Firebase initialized!");


// Save a complete scan record to Firestore
async function saveScan(record) {
    try {
        const user = await authReady;

        await setDoc(
            doc(db, "users", user.uid, "scans", record.id),
            {
                ...record,
                savedAt: serverTimestamp()
            }
        );

        console.log("Scan saved to Firestore:", record.id);
        return true;

    } catch (error) {
        console.error("Could not save scan to Firestore:", error);
        return false;
    }
}


// Retrieve all scans belonging to the current user
async function getScans() {
    try {
        const user = await authReady;

        const snapshot = await getDocs(
            collection(db, "users", user.uid, "scans")
        );

        return snapshot.docs.map(function (document) {
            return document.data();
        }).sort(function (a, b) {
            return new Date(b.createdAt) - new Date(a.createdAt);
        });

    } catch (error) {
        console.error("Could not load Firestore history:", error);
        return [];
    }
}

async function clearScans() {
    const user = await authReady;

    const snapshot = await getDocs(
        collection(db, "users", user.uid, "scans")
    );

    const deletions = snapshot.docs.map(function (document) {
        return deleteDoc(document.ref);
    });

    await Promise.all(deletions);

    console.log("All Firestore scans deleted.");
}

async function deleteScan(scanId) {
    const user = await authReady;

    await deleteDoc(
        doc(db, "users", user.uid, "scans", scanId)
    );

    console.log("Scan deleted from Firestore:", scanId);
}

// Make the save function available to other JavaScript files
window.ScamShieldFirebase = {
    saveScan: saveScan,
    getScans: getScans,
    deleteScan: deleteScan,
    clearScans: clearScans
};