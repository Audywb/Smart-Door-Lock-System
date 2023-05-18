import pyqrcode
import png

def generatorQR(id):
    link = f'http://dssipresent5.sci.ubu.ac.th/dashboard/door/user/unlock/{id}'
    qr_code = pyqrcode.create(link)
    qr_code.png(f'static/qrCode/{id}.png', scale=8)
    qr_code.show()