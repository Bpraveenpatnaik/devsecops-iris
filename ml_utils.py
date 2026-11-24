from sklearn import datasets
from sklearn.metrics import accuracy_score
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import GaussianNB

# define a Gaussian NB classifier
clf = GaussianNB()

# define the class encodings and reverse encodings
classes = {0: "Iris Setosa", 1: "Iris Versicolour", 2: "Iris Virginica"}
r_classes = {y: x for x, y in classes.items()}

FEATURES = ["sepal_length", "sepal_width", "petal_length", "petal_width"]

# training data, kept so that feedback is added to it instead of replacing it
X_train, y_train = [], []


def load_model():
    """Train the model on startup and print its accuracy on a held-out split."""
    global X_train, y_train
    X, y = datasets.load_iris(return_X_y=True)
    X_tr, X_test, y_tr, y_test = train_test_split(X, y, test_size=0.2, stratify=y, random_state=42)
    clf.fit(X_tr, y_tr)
    X_train, y_train = X_tr.tolist(), y_tr.tolist()

    acc = accuracy_score(y_test, clf.predict(X_test))
    print(f"Model trained with accuracy: {round(acc, 3)}")
    return acc


def predict(query_data):
    """Return the predicted class name for one flower."""
    x = [getattr(query_data, f) for f in FEATURES]
    prediction = clf.predict([x])[0]
    print(f"Model prediction: {classes[prediction]}")
    return classes[int(prediction)]


def retrain(data):
    """Add labelled feedback to the training data and refit.

    Refitting on the feedback alone would forget the original data and fail on
    a batch that only contains one class.
    """
    for d in data:
        X_train.append([getattr(d, f) for f in FEATURES])
        y_train.append(r_classes[d.flower_class])
    clf.fit(X_train, y_train)
