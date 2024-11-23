from flask import Flask, request, jsonify
from flask_mongoengine import MongoEngine
from flask import request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from flask_cors import CORS
import os
from dotenv import load_dotenv
from pymongo import MongoClient
from flask.json.provider import DefaultJSONProvider

Flask.json.JSONEncoder = DefaultJSONProvider


# .env dosyasını yükle
load_dotenv()

app = Flask(__name__)
CORS(app)

# Çevre değişkenleri
SECRET_KEY = os.getenv('SECRET_KEY', 'vatanmilletsakarya')
MONGODB_URI = os.getenv('MONGODB_URI', 'mongodb+srv://ibrahim:oZGNRekl3ltKTHxq@aracimipazarla.g7b0j.mongodb.net/aracimipazarla')
client = MongoClient(MONGODB_URI)

db = client['aracimipazarla']  # Veritabanı adı
collection = db['cars']
collection_sell = db.users_sell  # koleksiyon adı
collection_buy = db.users_buy  # koleksiyon adı

# MongoDB yapılandırması
app.config['MONGODB_SETTINGS'] = {
    'host': MONGODB_URI
}

db = MongoEngine()
db.init_app(app)

# Kullanıcı şeması
class User(db.Document):
    username = db.StringField(required=True)
    surname = db.StringField(required=True)
    email = db.StringField(required=True, unique=True)
    password = db.StringField(required=True)
    phone_number = db.StringField(required=True)
    location = db.StringField(required=True)
    meta = {"strict": False}

    meta = {
        'collection': 'users'
    }


# Kayıt işlemi
@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()

    # Kullanıcının gönderdiği veriyi ekrana yazdırma
    print(f"Gelen Veri: {data}")


    try:
        # Kullanıcıyı oluştur
        new_user = User(
            username=data['username'],
            surname=data['surname'],
            email=data['email'],
            password=generate_password_hash(data['password']),
            phone_number=str(data['phone_number']),
            location=data['location']
        )
        new_user.save()  # Veritabanına kaydet
        print(new_user)

        # Başarı mesajı
        return jsonify({'message': 'Kayıt başarılı!'}), 201

    except Exception as e:
        # Hata mesajını ekrana yazdırma
        print(f"Error: {str(e)}")
        return jsonify({'message': 'Kayıt sırasında hata oluştu', 'error': str(e)}), 500





# Giriş işlemi
@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()

    try:
        # E-posta ile kullanıcıyı bul
        user = User.objects.get(email=data['email'])
        
        # Şifre doğrulama
        if check_password_hash(user.password, data['password']):
            # Token oluşturma
            token = jwt.encode(
                {
                    'id': str(user.id),  # Kullanıcı ID'sini dahil et
                    'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)  # Token 24 saat geçerli
                },
                SECRET_KEY,
                algorithm="HS256"
            )

            return jsonify({'message': 'Giriş başarılı', 'token': token}), 200
        else:
            return jsonify({'message': 'E-posta veya şifre hatalı'}), 401

    except User.DoesNotExist:
        print("Kullanıcı bulunamadı")  # Hata mesajı ekleyebilirsiniz
        return jsonify({'message': 'E-posta veya şifre hatalı'}), 401
    except Exception as e:
        print(f"Bir hata oluştu: {str(e)}")  # Hata detayları
        return jsonify({'message': 'Bir hata oluştu', 'error': str(e)}), 500


def token_required(f):
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')  # 'Authorization' başlığından token al
        
        if not token:
            return jsonify({'message': 'Token eksik, yetkisiz erişim'}), 403

        try:
            # Token çözme
            data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            current_user = User.objects.get(id=data['id'])  # Token'dan kullanıcı bilgisi al
        except Exception as e:
            return jsonify({'message': 'Geçersiz token', 'error': str(e)}), 403

        return f(current_user, *args, **kwargs)

    decorated.__name__ = f.__name__  # Flask için dekoratör
    return decorated



# Ana sayfa erişim kontrolü
@app.route('/api/protected', methods=['GET'])
def protected():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'message': 'Token eksik!'}), 401

    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        return jsonify({'message': 'Token doğrulandı!', 'email': decoded['email']}), 200
    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Token süresi dolmuş!'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'message': 'Geçersiz token!'}), 401
    

@app.route('/api/user/profile', methods=['GET'])
@token_required
def user_profile(current_user):
    return jsonify({
        'username': current_user.username,
        'email': current_user.email,
        'location': current_user.location
    }), 200
    
    
@app.route('/api/cars', methods=['GET'])
def get_cars():
    try:
        # MongoDB'den tüm verileri al
        cars = list(collection.find({}, {"_id": 0}))  # _id alanını döndürme
        return jsonify(cars)
    except Exception as e:
        print(f"Error fetching data: {e}")
        return jsonify({"error": "Veri alınırken hata oluştu."}), 500
    
    
@app.route('/sellsave', methods=['POST'])
def save_car_info():
    data = request.json
    try:
        # Formdan alınan veriler
        car_info = {
            "brand": data.get("brand"),
            "model": data.get("model"),
            "detail": data.get("detail"),
            "year": data.get("year"),
            "km": data.get("km"),
            "isDamaged": data.get("isDamaged"),
            "appointment-date":data.get("date"),
            "additionalInfo": data.get("additionalInfo"),
            "paintedParts": data.get("paintedParts", []),  # Boyalı parçalar
            "changedParts": data.get("changedParts", [])
        }
        
        # Veriyi MongoDB'ye kaydetme
        result = collection_sell.insert_one(car_info)
        return jsonify({"message": "Araç bilgileri başarıyla kaydedildi!", "id": str(result.inserted_id)}), 201
    except Exception as e:
        return jsonify({"message": "Veri kaydedilirken hata oluştu", "error": str(e)}), 500
    


@app.route('/buysave', methods=['POST'])
def buy_car_info():
    data = request.json
    try:
        # Formdan alınan veriler
        buy_car_info = {
            "brand": data.get("brand"),
            "model": data.get("model"),
            "detail": data.get("detail"),
            "year": data.get("year"),
            "km": data.get("km"),
            "isDamaged": data.get("isDamaged"),
            "appointment-date":data.get("date"),
            "additionalInfo": data.get("additionalInfo"),
            "minprice":data.get("minPrice"),
            "maxprice":data.get("maxPrice")
        }
        
        # Veriyi MongoDB'ye kaydetme
        result = collection_buy.insert_one(buy_car_info)
        return jsonify({"message": "Araç bilgileri başarıyla kaydedildi!", "id": str(result.inserted_id)}), 201
    except Exception as e:
        return jsonify({"message": "Veri kaydedilirken hata oluştu", "error": str(e)}), 500


if __name__ == '__main__':
    app.run(debug=True, port=5000)
