from django.db import models
# from django.contrib.auth.models import User
from beposoft_app.models import*
from django.core.validators import MinValueValidator
from decimal import Decimal


class Category(models.Model):
    category_name = models.CharField(max_length=100,null=True)

class Choices(models.Model):
    name = models.CharField(max_length=100, null=True)
    
class Loan(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
    principal = models.DecimalField(max_digits=15, decimal_places=2, help_text="Total loan amount")
    emi_name = models.CharField(max_length=200, null=True)
    annual_interest_rate = models.DecimalField(max_digits=5, decimal_places=2, help_text="Annual interest rate in %")
    tenure_months = models.IntegerField(help_text="Loan duration in months", validators=[MinValueValidator(1)])
    processing_fee = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True, help_text="Optional processing fee")
    down_payment = models.DecimalField(max_digits=15, decimal_places=2, null=True, blank=True, help_text="Initial payment to reduce loan amount")
    prepayment_amount = models.DecimalField(max_digits=15, decimal_places=2, null=True, blank=True, help_text="Extra payment towards principal")
    startdate = models.DateField(null=True, blank=True)
    enddate = models.DateField(null=True, blank=True)

    # New fields to store calculated values
    emi_amount = models.DecimalField(max_digits=20, decimal_places=2, null=True, blank=True, help_text="Calculated EMI amount")
    total_interest = models.DecimalField(max_digits=20, decimal_places=2, null=True, blank=True, help_text="Total interest payable over the tenure")
    total_payment = models.DecimalField(max_digits=20, decimal_places=2, null=True, blank=True, help_text="Total payment (principal + interest)")

    def calculate_emi(self):
        """Calculate EMI using the standard formula."""
        P = self.principal - (self.down_payment or Decimal(0))
        R = (self.annual_interest_rate / 12) / 100
        N = self.tenure_months

        if R == 0:  # If zero interest
            return round(P / N, 2)

        emi = (P * R * (1 + R) ** N) / ((1 + R) ** N - 1)
        return round(emi, 2)

    def calculate_total_interest(self):
        """Calculate total interest payable over the tenure."""
        emi = self.calculate_emi()
        total_paid = emi * self.tenure_months
        P = self.principal - (self.down_payment or Decimal(0))
        total_interest = total_paid - P
        return round(total_interest, 2)

    def save(self, *args, **kwargs):
        """Override save method to store calculated values before saving."""
        self.emi_amount = self.calculate_emi()
        self.total_interest = self.calculate_total_interest()
        self.total_payment = self.principal + self.total_interest  # Total payment includes principal and interest
        super().save(*args, **kwargs)

    def __str__(self):
        return f"Loan: {self.principal} at {self.annual_interest_rate}% for {self.tenure_months} months"

class ExpenseModel(models.Model):
    ASSET_CHOICES = [
        ('assets', 'Assets'),
        ('expenses', 'Expenses')
    ]

    company = models.ForeignKey(Company, on_delete=models.CASCADE, related_name="company")
    payed_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name="payed_by")
    bank = models.ForeignKey(Bank, on_delete=models.CASCADE, related_name="banks")
    category = models.ForeignKey(Category, on_delete=models.CASCADE, null=True)
    name = models.CharField(max_length=100, null=True)
    quantity = models.IntegerField(null=True, blank=True)
    purpose_of_payment = models.ForeignKey(Choices, on_delete=models.SET_NULL, null=True, related_name="expenses")
    amount = models.DecimalField(max_digits=10, decimal_places=2, null=True)
    expense_date = models.DateField()
    transaction_id = models.CharField(max_length=100)
    description = models.TextField()
    added_by = models.CharField(max_length=30, null=True)
    loan = models.ForeignKey(Loan, on_delete=models.CASCADE, null=True, blank=True, related_name="loan_expenses")
    asset_types = models.CharField(max_length=100, choices=ASSET_CHOICES, null=True)

    def save(self, *args, **kwargs):
        """Ensure EMI payments are linked to a loan before saving."""
        if self.purpose_of_payment:
            purpose = Choices.objects.filter(id=self.purpose_of_payment.id).first()
            if purpose:
                print(f"Saving Expense: Purpose={purpose.name}, Loan ID={self.loan}")  # Debugging output
                if purpose.name.lower() == 'emi' and not self.loan:
                    raise ValidationError("EMI payments must be associated with a loan.")

        super().save(*args, **kwargs)

    def __str__(self):
        return f"Expense: {self.amount} for {self.purpose_of_payment} on {self.expense_date}"
    



