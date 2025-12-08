from django.urls import path
from .views import *

urlpatterns = [
    
    path('api/dashboard/', DashboardView.as_view(), name='dashboard'),

    path('api/register/', UserRegistrationAPIView.as_view(), name='user-registration'),
    path('api/login/', UserLoginAPIView.as_view(), name='user-login'),
    path('api/login/<str:token>/', TokenLoginAPIView.as_view(), name='token_login'),


    path('api/profile/',UserProfileData.as_view(),name="UserProfileData"),

    path("api/customer-types/", CustomerTypeView.as_view(), name="customer-type-list-create"),
    path("api/customer-types/<int:pk>/", CustomerTypeView.as_view(), name="customer-type-detail"),
    
    path('api/add/customer/', UserCustomerAddingView.as_view(), name='add-customer'),
    path('api/customers/', CustomerView.as_view(), name='customer-list'),
    path('api/staff/customers/', StaffBasedCustomers.as_view(), name='customer-list'),
    path('api/customer/update/<int:pk>/', CustomerUpdateView.as_view(), name='customer-update'),


    path('api/add/staff/',CreateUserView.as_view(),name="add-staff"), 
    path('api/add/staff2/',CreateUser2View.as_view(),name="add-staff2"), 
    path('api/staffs/',Users.as_view(),name="staffs"), 
    path('api/staff/orders/',StaffOrders.as_view(),name="staffs"),
    path('api/manager/customers/',ManagerUnderCustomer.as_view(),name="staffs"), 
    path('api/staff/update/<int:pk>/',UserDataUpdate.as_view(),name="staff-update"),


    path('api/add/family/',FamilyCreatView.as_view(),name="add-family"),  # completed 
    path('api/familys/',FamilyAllView.as_view(),name="familys"),  # completed
    path('api/family/orders/',FamilyBasedOrderGetView.as_view(),name="familys"),  # completed
    path('api/family/update/<int:pk>/',FamilyUpdateView.as_view(),name="family-update"),  # completed
    path('api/country/codes/', CountryCodeView.as_view(), name='country-code'),
    path('api/country/codes/<int:pk>/', CountryCodeDetailView.as_view(), name='country-code-detail'),


    path('api/add/product/',ProductCreateView.as_view(),name="add-product"), # completed
    path('api/products/',ProductListView.as_view(),name="products"), # completed
    path('api/all/products/',ListAllProducts.as_view()),
    path('api/product/update/<int:pk>/',ProductUpdateView.as_view(),name="product-update"),
    path('api/approved/products/',ApprovedProductList.as_view()),
    path('api/disapproved/products/', DisapprovedProductList.as_view()),


    path('api/add/department/',DepartmentCreateView.as_view(),name="add-department"),  # completed
    path('api/departments/',DepartmentListView.as_view(),name="departments"), # completed
    path('api/department/update/<int:pk>/',DepartmentsUpdateView.as_view(),name="department-update"), # completed
    
    
    path ('api/image/delete/<int:pk>/',SingleProductImageView.as_view(),name="image-delete"),  # completed
    path('api/image/add/<int:pk>/',SingleProductImageCreateView.as_view(),name="images-add"),  # completed


    path('api/add/state/',StateCreateView.as_view(),name="add-state"),  # completed
    path('api/states/',StateListView.as_view(),name="states"), # completed
    path('api/state/update/<int:pk>/',StateUpdateView.as_view(),name="state-update"), # completed


    path('api/add/supervisor/',SupervisorCreateView.as_view(),name="add-supervisor"), # completed
    path('api/supervisors/',SuperviserListView.as_view(),name="supervisors"),# completed
    path('api/supervisor/update/<int:pk>/',SupervisorUpdateView.as_view(),name="supervisor-update"),# completed


    path('api/add/customer/address/<int:pk>/',ShippingCreateView.as_view(),name="add-customer-address"),# completed
    path('api/update/cutomer/address/<int:pk>/',CustomerShippingAddressUpdate.as_view(),name="address-update"), 
    path('api/address/get/<int:address_id>/',ShippingDetailView.as_view()),


    path('api/add/product/variant/',VariantProductCreate.as_view(),name="add-variant-product"),# completed
    path('api/products/<int:pk>/variants/', VariantProductsByProductView.as_view(), name='variant-products-by-product'), # completed
    


    path('api/add/product/attributes/',ProductAttributeCreate.as_view(),name="add-product-attributes"),
    path('api/product/attributes/',ProductAttributeListView.as_view(),name="product-attributes"),
    path('api/product/attribute/<int:pk>/delete/',ProductAttributeView.as_view(),name="delete-product-attributes"),


    path('api/add/product/attribute/values/',ProductAttributeCreateValue.as_view(),name="add-product-attribute-values"),
    path('api/product/attribute/<int:pk>/values/',ProductAttributeListValue.as_view(),name="product-attribute-values"),
    path('api/product/attribute/<int:pk>/update/',ProductAttributeValueUpdate.as_view(),name="product-attribute-update"),
    path('api/product/attribute/delete/<int:pk>/values/',ProductAttributeValueDelete.as_view(),name="delete-product-attribute-values"),


    path('api/order/create/', CreateOrder.as_view(), name='create-order'),
    path('api/orders/', OrderListView.as_view(), name='orders'),
    path('api/gst/orders/', GSTOrderListView.as_view(), name='gst'),
    path('api/orders/<str:status_value>/', OrderListByStatusView.as_view(), name='orders-status'),
    path('api/orders/summary/family/data/', FamilyOrderSummaryView.as_view(), name='family-order-summary'),
    path("api/orders/date/report/<str:start_date>/<str:end_date>/", OrderDateReportView.as_view(), name="order-date-report"),
    path('api/orders/parcel/service/data/', ParcelServiceGroupedView.as_view(), name="parcel-service-warehouse-data"),
    path('api/orders/update/<int:pk>/',OrderUpdateView.as_view()),
    path('api/order-item/create/', OrderItemCreateView.as_view(), name='order-item-create'),
    path('api/order/images/upload/', OrderImageUploadView.as_view(), name='order-image-upload'),
    path('api/order/images/<int:order_id>/', OrderImageView.as_view(), name='order-image'),
    path('api/order/images/delete/<int:image_id>/', DeleteOrderImageView.as_view(), name='delete-order-image'),
    path('api/order/payment/images/upload/', OrderPaymentImageUploadView.as_view(), name='order-image-upload'),
    path('api/order/payment/images/<int:order_id>/', OrderPaymentImageView.as_view(), name='order-image'),
    path('api/order/payment/images/delete/<int:image_id>/', DeleteOrderPaymentImageView.as_view(), name='delete-order-image'),
    # path('api/customer/update/<int:pk>/', CustomerUpdateView.as_view(), name='customer-update'),
    path('api/product-wise/report/', ProductWiseReportView.as_view(), name='product-wise-report'),
    path('api/product-wise/filter/report/', ProductWiseFilterReportView.as_view(), name='product-wise-report'),
    path('api/warehouse/order/create/', CreateWarehouseOrder.as_view(), name='create-warehouse-order'),
    path('api/warehouse/order/view/', WarehouseOrderView.as_view(), name='view-warehouse-order'),
    path('api/warehouse/order/view/<str:invoice>/', WarehouseOrderIDView.as_view(), name='view-warehouse-order-by-id'),
    path('api/warehouse/order/view/invo/<int:warehouse_id>/', WarehouseOrderByWarehouseView.as_view(), name='view-warehouse-order-id'),
    path('api/warehouse/order/update/<int:pk>/', WarehouseOrderUpdateView.as_view(), name='update-warehouse-order-id'),
    path('api/warehouse/order/item/update/<int:pk>/', WarehouseOrderItemUpdateView.as_view(), name='update-warehouse-order-item-id'),
    
    # locking and unlocking the delivery note
    path('api/orders/<int:order_id>/lock/', LockOrderView.as_view(), name='lock_order'),
    path("api/orders/unlock/<int:order_id>/", UnlockOrderView.as_view(), name="unlock_order"),
    
    path('api/order/<int:order_id>/items/', CustomerOrderItems.as_view(), name='order-items'),
    # path('api/order/status/update/<int:pk>/', CustomerOrderStatusUpdate.as_view(), name='status-update-order'),
    path('api/shipping/<int:pk>/order/',ShippingManagementView.as_view(),name = "shipping-management"),
    path('api/add/order/<int:pk>/product/',ExistedOrderAddProducts.as_view()),
    path('api/remove/order/<int:pk>/item/',RemoveExistsOrderItems.as_view()),
    

    path('api/staff/customers/',StaffCustomersView.as_view(),name="staff-customers"),
    path('api/cart/product/', Cart.as_view(), name='add-product-cart'),
    path('api/cart/products/',StaffcartStoredProductsView.as_view()),
    path('api/cart/update/<int:pk>/',StaffDeleteCartProduct.as_view()),
    path('api/cart/delete/all/',StaffDeleteCartProductAll.as_view()),
    path('api/cart/price/',UpdateCartPricesView.as_view()),
    
    path('api/add/bank/',CreateBankAccountView.as_view()),
    path('api/banks/',BankView.as_view()),
    path('api/bank/view/<int:pk>/',BankAccountView.as_view()),
    path('api/company/data/',CreateCompnayDetailsView.as_view()),
    
    
    
    path('api/payment/<int:pk>/reciept/',CreateReceiptAgainstInvoice.as_view()),
    path('api/customer/<int:pk>/ledger/',CustomerOrderLedgerdata.as_view()),
    path('api/recieptsupdate/get/<int:id>/',ReceiptViewbyId.as_view()),
    path('api/advancereceipt/',CreateAdvanceReceipt.as_view()),
    path('api/bank-receipts/', BankReceiptListCreateView.as_view()),
    path('api/allreceipts/view/', AllReceiptsView.as_view()),
    path('api/advancereceipt/view/', AdvanceReceiptListView.as_view()),
    path('api/bankreceipt/view/', BankReceiptListView.as_view()),
    path('api/orderreceipt/view/', OrderReceiptListView.as_view()),
    path('api/advancereceipt/view/<int:pk>/', AdvanceReceiptDetailView.as_view(), name='advance-receipt-detail'),
    path('api/bankreceipt/view/<int:pk>/', BankReceiptDetailView.as_view(), name='bank-receipt-detail'),
    path('api/orderreceipt/view/<int:pk>/', OrderReceiptDetailView.as_view(), name='order-receipt-detail'),
    
    
    path('api/perfoma/invoice/create/',CreatePerfomaInvoice.as_view()),
    path('api/perfoma/invoices/',PerfomaInvoiceListView.as_view()),
    path('api/perfoma/<str:invoice>/invoice/',PerfomaInvoiceDetailView.as_view()),
    path('api/performa/invoice/staff/',PerformaOrderStaff.as_view()),
    path('performainvoice/<str:invoice_number>/', GeneratePerformaInvoice, name='generate_invoice'),
    
    
    path('api/warehouse/data/',WarehouseDataView.as_view()),
    path('api/warehouse/detail/<int:pk>/',WarehouseDetailView.as_view()),
    path('api/warehouse/box/detail/',DailyGoodsView.as_view()),            #deliveryreport
    path('api/warehousedata/<str:date>/',DailyGoodsBydate.as_view()),
    path('api/warehouse/get/',WarehouseListView.as_view()),
    path('api/warehouse/get/summary/', WarehouseSummaryView.as_view()),
    path('api/warehousesdataget/<str:shipped_date>/', WarehouseListViewbyDate.as_view(), name='warehouse-list'),
    path('warehouse/update-checked-by/<str:shipped_date>/', WarehouseUpdateCheckedByView.as_view(), name='update-checked-by'),
    path('api/orders/monthly/<int:year>/<int:month>/', OrderListByMonthView.as_view(), name='orders-by-month'),
    path('api/orders/status/count/', OrderStatusCount.as_view(), name='orders-count-status'),


    path('api/grv/data/',GRVaddView.as_view()),
    path('api/getgrv/<int:pk>',GRVGetViewById.as_view()),
    path('api/grv/update/<int:pk>/',GRVUpdateView.as_view()),
    

    path('api/expense/add/',ExpensAddView.as_view()),
    path('api/expense/get/<int:pk>/',ExpenseUpdate.as_view()),
    path('api/expense/addexpectemi/',ExpensAddViewExpectEmi.as_view()),
    path('api/assest/',ExpensAddAssestView.as_view()),
    path('api/asset/update/<int:pk>/',ExpensAddAssestView.as_view()),
    path('api/expense/addexpectemiupdate/<int:pk>/',ExpensAddViewExpectEmiUpdate.as_view()),
    path("api/get/expense/<int:id>/", ExpenseDetailView.as_view(), name="expense-detail"),

    path('api/product/date/wise/report/', ProductDateWiseReportView.as_view(), name='product_date_wise_report'),

    path('api/salesreport/',SalesReportView.as_view()),
    path('api/invoice/report/<str:date>/',InvoiceReportView.as_view()),

    path('api/bills/<str:date>/<int:pk>/',BillsView.as_view()),
    path('api/credit/sales/',CreditSalesReportView.as_view()),
    
    path('api/credit/bills/<str:date>/',CreditBillsView.as_view()),
    path('api/COD/sales/',CODSalesReportView.as_view()),
    path('api/COD/bills/<str:date>/',CODBillsView.as_view()),
    path('api/state/wise/report/',StatewiseSalesReport.as_view()),
    path('api/stateorder/detail/<int:state_id>/',StateOrderDetailsView.as_view()),

    path('api/deliverylist/report/<str:date>/',DeliveryListView.as_view()),
    path('api/sold/products/',ProductSalesReportView.as_view()),
    
    path('api/product/stock/report/',ProductStockReportView.as_view()),
    path('api/finance-report/',FinancereportAPIView.as_view()),
    path('api/receipts/get/',AllpaymentReceiptsView.as_view()),
    path('api/internal/transfers/', InternalTransferView.as_view(), name='internal_transfers'),
    path('api/internal/transfers/<int:id>/', InternalTransferByIdView.as_view(), name='internal_transfer_by_id'),

    
    
    path('api/parcal/service/',ParcalServiceView.as_view()),
    path('api/parcal/<int:pk>/service/',EditParcalService.as_view()),
    path('api/bulk/upload/products/',ProductBulkUploadAPIView.as_view()),
    path('api/bulk/upload/orders/',OrderBulkUploadAPIView.as_view()),
    path('api/bulk/upload/customers/',CustomerUploadView.as_view()),
    path('invoice/<int:pk>/', GenerateInvoice, name='generate_invoice'),
    path('deliverynote/<int:order_id>/', Deliverynote, name='delivery_note'),
    path('warehouse/deliverynote/<int:order_id>/', warehouse_delivery_note, name='delivery_note'),
    path('shippinglabel/<int:order_id>/',generate_shipping_label,name="generate_shipping_label"),


    path('api/rack/add/',RackDetailsView.as_view()),
    path('api/rack/add/<int:pk>/', RackDetailByIdView.as_view(), name='rack-detail-by-id'),
    path('api/product/category/add/', ProductCategoryView.as_view()),
    path('api/warehouse/add/',WarehouseAddView.as_view()),
    path('api/warehouse/update/<int:pk>/',WarehouseGetView.as_view()),
    path('api/warehouse/products/<int:warehouse_id>/',ProductByWarehouseView.as_view()),
    path('api/product/<int:product_id>/locked-invoices/', LockedStockInvoicesView.as_view()),
    path('api/warehouse/orders/<int:warehouse_id>/',WareHouseOrdersView.as_view()),

   
    path('api/attendance/',AttendanceView.as_view()),
    path('api/attendance/update/<int:pk>/', AttendanceUpdateAPIView.as_view(), name='attendance_update'),
    path('api/attendance/report/all/', AllStaffAttendanceReportAPIView.as_view(), name='all_staff_attendance_report'),
    path('api/attendance/absence/<int:staff_id>/', StaffAttendanceAbsenceAPIView.as_view(), name='attendance_absence'),


    
    path('api/sendtrackingid/', SendShippingIDView.as_view(), name='send-shipping-id'),

    path('api/call-log/create/<int:created_by_id>/', CallLogDataView.as_view(), name='calllog-create'),
    path('api/call-log/view/', CallLogView.as_view(), name='calllog-view'),
    
    path('api/datalog/create/', DataLogCreateView.as_view(), name='datalog-create'),
    path('api/datalog/delete/', DeleteOldDataLogsView.as_view(), name='datalog-create'),
    path('api/datalog/', DataLogListView.as_view(), name='datalog-list'),

    path('api/districts/add/', DistrictView.as_view(), name='add-districts'),
    path('api/districts/update/<int:id>/', DistrictDetailView.as_view(), name='update-districts'),

    
    path("api/contact/info/", ContactInfoCreateView.as_view(), name="contact-info-create"),
    path("api/contact/info/<int:pk>/", ContactInfoUpdateView.as_view(), name="contact-info-update"),
    path("api/contact/info/staff/<int:created_by>/", ContactInfoByStaffView.as_view(), name="staff-contact-info-update"),
    path("api/call/report/", CallReportCreateView.as_view(), name="call-report-create"),
    path("api/call/report/<int:pk>/", CallReportUpdateView.as_view(), name="call-report-update"),
    path('api/call/report/date/<str:date>/', CallReportByDateView.as_view(), name='call-report-by-date'),
    path('api/call/report/staff/<int:created_by>/', CallReportByStaffView.as_view(), name='call-report-by-staff'),
    path('api/call/report/state/<int:state_id>/', CallReportByStateView.as_view(), name='call-report-by-state'),
    path('api/call/report/filter/', CallReportFilterView.as_view(), name='call-report-filter'),
    path('api/call/report/summary/', CallReportSummaryView.as_view(), name='call-report-summary'),

    path('api/staff/custom/order/update/', StaffOrderUpdateView.as_view()),
    path('api/staff/custom/order/update/<int:pk>/', StaffOrderUpdateDetailView.as_view()),
    path('api/customers/manager/<int:manager_id>/', CustomerByManagerView.as_view()),

    path('api/questionnaires/', QuestionnaireView.as_view(), name='questionnaire_view'),
    path('api/questionnaires/<int:pk>/', QuestionnaireDetailView.as_view(), name='questionnaire_detail_update'),
    path('api/answers/', AnswersView.as_view(), name='answers_list_create'),
    path('api/answers/<int:pk>/', AnswersDetailView.as_view(), name='answers_detail_update'),
    path("api/questionnaires/family/<int:family_id>/", QuestionnaireByFamilyView.as_view(),name="questionnaires-by-family"),
    path("api/answers/family/<int:family_id>/", AnswersByFamilyView.as_view(),name="answers-by-family"),

]

