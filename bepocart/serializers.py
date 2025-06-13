from rest_framework import serializers
from beposoft_app.models import *
from .models import*




class ProductSerilizers(serializers.ModelSerializer):
    class Meta :
        model = Products
        fields = "__all__"
        



class LoanSerializer(serializers.ModelSerializer):
    emi = serializers.SerializerMethodField()
    class Meta: 
        model = Loan
        fields = "__all__"
    def get_emi(self, obj):
        return obj.calculate_emi()      


class ProductAssetsSerializer(serializers.ModelSerializer):
    class Meta:  
        model = Products
        fields = ["name", "stock", "landing_cost"]

class ExpenseAssetsSerializer(serializers.ModelSerializer):
    class Meta:
        model = ExpenseModel
        fields = ["name", "quantity", "amount"]

class CategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = Category
        fields = "__all__"
       

class PurposeSerializer(serializers.ModelSerializer):
    class Meta:
        model=Choices
        fields="__all__"
