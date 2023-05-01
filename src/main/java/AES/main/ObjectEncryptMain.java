package AES.main;

import AES.util.AESUtil;

import javax.crypto.SealedObject;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.Serializable;
import java.util.Objects;

public class ObjectEncryptMain {

    public static void main(String[] args) {

        try {
           Employee employee = new Employee("David",21);
            SecretKey secretKey = AESUtil.generateKey(128);
            IvParameterSpec ivParameterSpec = AESUtil.generateIV();
            String algorithm = "AES/CBC/PKCS5Padding";
            SealedObject encryptObject = AESUtil.encryptObject(algorithm,employee,secretKey,ivParameterSpec);
            Employee decryptObject = (Employee) AESUtil.decryptObject(algorithm,encryptObject,secretKey,ivParameterSpec);

            System.out.println("DecryptObject : "+decryptObject);
            System.out.println(employee.equals(decryptObject));
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }
}

class Employee implements Serializable {
    private String name;
    private int age;

    public Employee(String name, int age) {
        this.name = name;
        this.age = age;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public int getAge() {
        return age;
    }

    public void setAge(int age) {
        this.age = age;
    }

    @Override
    public String toString() {
        return "Employee{" +
                "name='" + name + '\'' +
                ", age=" + age +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Employee employee = (Employee) o;
        return age == employee.age && Objects.equals(name, employee.name);
    }

}