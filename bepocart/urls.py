from django.urls import path
from .views import *




urlpatterns = [
    path('products/',ProductListView.as_view()),
    path('emi/', EmiView.as_view(), name='emi'),
    path('loan/<int:pk>/', LoanDetailView.as_view(), name='loan-detail'),
    path('loan/emi/<int:loan_id>/', LoanEMIView.as_view(), name='loan-emi'),
    path('emiexpense/<int:emi_id>/', EmiExpenseView.as_view(), name='emi-expense-detail'),
    path('assests/get/',AssetsAPIView.as_view()),
    path('liability/get/',LiabilitiesAPIView.as_view()),
    path('add/assetcategory/',CategoryaddView.as_view()),
    path('update/delete/assetcategory/<int:pk>/',Categorydetailview.as_view()),
    path('get/asset/report/',AssetReport.as_view()),
    path('add/purpose/',PurposeaddView.as_view()),
    path('purpose/update/<int:pk>/',PurposeUpdate.as_view()),


]


