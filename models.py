from django.conf import settings
from django.db import models
from django.db.models.signals import post_save
from django.utils import timezone

User = settings.AUTH_USER_MODEL


class MuseWallet(models.Model):
    kauri = models.FloatField(default=0)
    timestamp = models.DateTimeField(default=timezone.now)


TransactionType = (
    ('Transfer', 'Transfer'),
    ('Purchase', 'Purchase')
)

TransactionMedium = (
    ('Cryptocurrency', 'Cryptocurrency'),
    ('Flutterwave', 'Flutterwave')
)


class WalletManager(models.Manager):
    def get_user_wallet(self, user):
        wallet_qs = self.filter(user=user)
        if wallet_qs.exists():
            return wallet_qs.first()
        return None


class Wallet(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    kauri = models.FloatField(default=0)
    transaction_type = models.CharField(choices=TransactionType, max_length=80)
    transaction_medium = models.CharField(choices=TransactionMedium, null=True, blank=True, max_length=80)
    timestamp = models.DateTimeField(default=timezone.now)
    objects = WalletManager()

    def __str__(self):
        return f'{self.user.username}-- {self.kauri}'


class Transaction(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    amount = models.FloatField(default=0)
    transaction_type = models.CharField(choices=TransactionType, max_length=80)
    message = models.CharField(max_length=400)
    kauri = models.FloatField(default=0)
    successful = models.BooleanField(default=False)
    transaction_medium = models.CharField(choices=TransactionMedium, null=True, blank=True, max_length=80)
    timestamp = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ('-id',)

    def __str__(self):
        return f"{self.user.username} -- {self.amount} -- {self.transaction_medium} -- {self.transaction_type}"


# in here i am creating a wallet once the user is being created
def post_save_wallet(sender, instance, created, *args, **kwargs):
    if created:
        Wallet.objects.get_or_create(user=instance)
    user_wallet, created = Wallet.objects.get_or_create(user=instance)
    user_wallet.save()


post_save.connect(post_save_wallet, sender=User)

TRANSACTION_STAGE = (
    ('INITIAL', 'INITIAL'),
    ('PROGRESS', 'PROGRESS'),
    ('COMPLETED', 'COMPLETED'),
)


class FlutterWaveTransactionReference(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    transaction_stage = models.CharField(choices=TRANSACTION_STAGE, max_length=100)
    transaction_reference = models.CharField(max_length=100, unique=True, blank=True, null=True)
    flutterwave_reference = models.CharField(max_length=100, unique=True, blank=True, null=True)
    timestamp = models.DateTimeField(default=timezone.now())
