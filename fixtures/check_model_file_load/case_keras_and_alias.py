import tensorflow as tf

m = tf.keras.models.load_model(path)
w = torch.load("w.pt", weights_only=False)
