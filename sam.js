//Unique Firebase Object
const firebaseConfig = {
  apiKey: "AIzaSyAgnItfkftEo5lnd8k-deecyUq9K_jEpDA",
  authDomain: "eccommerce-d5528.firebaseapp.com",
  databaseURL: "https://eccommerce-d5528-default-rtdb.firebaseio.com",
  projectId: "eccommerce-d5528",
  storageBucket: "eccommerce-d5528.appspot.com",
  messagingSenderId: "693553442191",
  appId: "1:693553442191:web:b60a1a647e6a9cc26ceffa"
};

//Initialize Firebase
firebase.initializeApp(firebaseConfig);
var firestore = firebase.firestore();

//Variable to access database collection
const db = firestore.collection("fomData");

//Get Submit Form
let submitButton = document.getElementById("submit");

//Create Event Listener To Allow Form Submission
submitButton.addEventListener("click", (e) => {
  //Prevent Default Form Submission Behavior
  e.preventDefault();

  //Get Form Values
  let firstName = document.getElementById("fname").value;
  let lastName = document.getElementById("lname").value;
  let country = document.getElementById("country").value;

  firestore
    .collection("fomData")
    .get()
    .then((snapshot) => {
      snapshot.docs.forEach((doc) => {
        const fn = doc.data().fname;
        if (firstName === fn) {
          console.log("Already Exists");
        }

        // console.log("data", doc.data().fname);
      });
    });
  //Save Form Data To Firebase
  db.doc()
    .set({
      fname: firstName,
      lname: lastName,
      country: country,
    })
    .then(() => { })
    .catch((error) => {
      console.log(error);
    });

  //alert
  alert("Your Form Has Been Submitted Successfully");

  //clear form after submission
  function clearForm() {
    document.getElementById("clearFrom").reset();
  }
  clearForm()
});
