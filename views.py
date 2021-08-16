import json

import requests
from decouple import config
from django.conf import settings
from django.contrib.auth import get_user_model
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
from rave_python import Rave, RaveExceptions, Misc
from rest_framework.generics import ListAPIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.status import HTTP_200_OK, HTTP_400_BAD_REQUEST
from rest_framework.views import APIView

from .models import Transaction, FlutterWaveTransactionReference
from .models import Wallet
from .serializers import WalletSerializer, TransactionSerializer, TransferKauriSerializer, \
    CardSerializer, AddressSerializer
from .utils import transfer_kauri, fund_wallet, create_transaction
import ast

# import unirest  # unirest is a http library. You can use any http library you prefer

RAVE_PUBLIC_KEY = settings.RAVE_PUBLIC_KEY
RAVE_SECRET_KEY = settings.RAVE_SECRET_KEY

rave = Rave(RAVE_PUBLIC_KEY, RAVE_SECRET_KEY, usingEnv=False)

User = get_user_model()


class WalletAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        wallet = Wallet.objects.get_user_wallet(self.request.user)
        if wallet:
            serializer = WalletSerializer(wallet).data
            return Response(serializer, status=HTTP_200_OK)
        return Response({"message": "There was an error performing your request"}, status=HTTP_400_BAD_REQUEST)


class TransactionListAPIView(ListAPIView):
    serializer_class = TransactionSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        transaction = Transaction.objects.filter(user=self.request.user)
        if transaction:
            return transaction
        else:
            return transaction.none()


class TransferKauriAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = TransferKauriSerializer(data=request.data)
        serializer.is_valid()
        from_user = self.request.user
        to_user = User.objects.filter(username=serializer.data.get('username'),
                                      email=serializer.data.get('email')).first()
        kauri = serializer.data.get('kauri')
        if from_user and to_user and kauri:
            response = transfer_kauri(from_user=from_user, to_user=to_user, kauri=kauri)
            if response:
                return Response({'message': f'Successfully transferred {kauri} to {to_user.username}'},
                                status=HTTP_200_OK)
        return Response({'message': f'There was an error performing your request '}, status=HTTP_400_BAD_REQUEST)


class CardPaymentAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = CardSerializer(data=self.request.data)
        serializer.is_valid(raise_exception=True)
        address_serializer = AddressSerializer(data=self.request.data)
        address_serializer.is_valid(raise_exception=True)
        payload = {'email': request.user.email}
        payload.update(serializer.data)
        try:
            res = rave.Card.charge(payload)
            if res["suggestedAuth"]:
                arg = Misc.getTypeOfArgsRequired(res["suggestedAuth"])
                if arg == "pin":
                    Misc.updatePayload(res["suggestedAuth"], payload, pin=payload['pin'])
                if arg == "address":
                    Misc.updatePayload(res["suggestedAuth"], payload, address=address_serializer.data)
            if res["validationRequired"]:
                data = {'amount': payload['amount']}
                data.update(res)
                # saving obj in session
                request.session[f'{request.user.username}FL'] = data
                return Response({'message': res.get('chargemessage')}, status=HTTP_200_OK)
        except Exception as a:
            return Response({'message': f'{a}'}, status=HTTP_400_BAD_REQUEST)


class ApplyCardOTP(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        otp = request.data.get('otp')
        if otp:
            try:
                res = request.session.get(f'{request.user.username}FL')
                if res["validationRequired"]:
                    rave.Card.validate(res["flwRef"], otp)
                response = rave.Card.verify(res["txRef"])
                if response["transactionComplete"]:
                    create_transaction(user=request.user, amount=res['amount'],
                                       message="Payment was successful through flutterwave", successful=True)
                    fund_wallet(self.request.user, res['amount'])
                    return Response({'message': 'payment was successful'}, status=HTTP_200_OK)
            except RaveExceptions.CardChargeError as e:
                create_transaction(user=request.user, amount=res['amount'], message=e.err["errMsg"], successful=False)
                return Response({'message': e.err["errMsg"]}, status=HTTP_400_BAD_REQUEST)
            except RaveExceptions.TransactionValidationError as e:
                create_transaction(user=request.user, amount=res['amount'], message=e.err["errMsg"], successful=False)
                return Response({'message': e.err["errMsg"]}, status=HTTP_400_BAD_REQUEST)
            except RaveExceptions.TransactionVerificationError as e:
                create_transaction(user=request.user, amount=res['amount'], message=e.err["errMsg"], successful=False)
                return Response({'message': e.err["errMsg"]}, status=HTTP_400_BAD_REQUEST)
        return Response({'message': ' Please send your otp'}, status=HTTP_400_BAD_REQUEST)


class InitializeTransactionAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        transaction_reference = f'{request.user.username}tx_ref{request.user.id}'
        flutter_ref, created = FlutterWaveTransactionReference.objects.get_or_create(
            user=request.user)
        flutter_ref.transaction_stage = 'INITIAL'
        flutter_ref.save()
        print(flutter_ref)
        return Response({'message': 'Successfully initialized transaction'}, status=HTTP_200_OK)


@require_POST
@csrf_exempt
def webhook_view(request):
    # Retrieve the request's body
    response = request.body
    request_json = response.decode('utf-8')
    data = ast.literal_eval(request_json)
    data = data.get('data')
    # Do something with request_json
    if data['status'] == 'successful':
        url = config('RAVE_VERIFY_URL')
        # make the http post request to our server with the parameters
        tx_ref = data['tx_ref']
        response = requests.post(url, headers={"Content-Type": "application/json"}, params={
            'txref': tx_ref,
            'SECKEY': config('WEBHOOK_HASH')
        })
        print(response)
        print(response.status_code)
        print(response.json())
        return HttpResponse({'message': 'payment was successful'}, status=200)
    return HttpResponse({'message': 'payment was unsuccessful'}, status=400)
