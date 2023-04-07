<?php

namespace kozlovsv\jwtauth;
use UnexpectedValueException;

/**
 * Exception throws if token not in WhiteList
 * @package kozlovsv\jwtauth
 * @author Kozlov Sergey <kozlovsv78@gmail.com>
 */
class BlockedException extends UnexpectedValueException
{
}