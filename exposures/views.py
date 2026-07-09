from django.contrib.auth.decorators import login_required
from django.shortcuts import render


@login_required
def overview(request):
    return render(request, "exposures/overview.html", {})
