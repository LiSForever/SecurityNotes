* 使用dependency-check-maven进行第三方jar包的检测

```xml
 <plugin>
    <groupId>org.owasp</groupId>
    <artifactId>dependency-check-maven</artifactId>
    <version>5.2.4</version>
    <configuration>
        <autoUpdate>true</autoUpdate>
    </configuration>
    <executions>
        <execution>
            <goals>
                <goal>check</goal>
            </goals>
        </execution>
    </executions>
</plugin>
```

