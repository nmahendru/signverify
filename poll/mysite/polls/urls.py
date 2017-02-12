from django.conf.urls import url

from . import views

urlpatterns = [
    url(r'test$', views.index, name='index'),
    url(r'verify$', views.verify, name='verify'),

]
